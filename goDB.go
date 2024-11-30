package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/ristretto/z"
	"github.com/gofrs/uuid"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ### CONST ###

const defaultIxCapacity = 2_000_000
const defaultIxValueMaxLength = 100

// ### TYPES ###

type EntryResponse struct {
	uUID string
	Data []byte
}

type MassEntryResponse struct {
	uUID   string
	Data   []byte
	Counts map[int][]int
}

type DBSettings struct {
	ixCapacity  int64
	ixMaxLength int
}

type GoDB struct {
	db      *badger.DB
	workDir string
	module  string
	DBSettings
}

type SelectOptions struct {
	MaxResults int64
	Page       int64
	Skip       int64
}

// ### Public Functions ###

// OpenDB creates a named database (e.g. users), initialized with the provided named indices (e.g. username)
func OpenDB(module string) *GoDB {
	// Set working directory
	workDirTmp, _ := os.Getwd()
	dbPath := checkModuleDir(module, workDirTmp)
	if dbPath == "" {
		log.Fatal("FATAL ERROR: Could not create database")
	}
	// Create DB files if missing
	badgerDB, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		log.Fatal(err)
	}
	// Create db struct pointer and return
	goDB := &GoDB{
		db:      badgerDB,
		workDir: workDirTmp,
		module:  module,
		DBSettings: DBSettings{
			ixCapacity:  defaultIxCapacity,
			ixMaxLength: defaultIxValueMaxLength,
		},
	}
	return goDB
}

func (db *GoDB) CloseDB() error {
	if db.db == nil {
		return nil
	}
	err := db.db.Close()
	if err != nil {
		fmt.Println(err)
	}
	return nil
}

// ### DB Functions ###

// Insert adds an entry to the database
func (db *GoDB) Insert(
	mod string, data []byte, indices map[string]string,
) (string, error) {
	indicesClean, _ := db.validateIndices(indices, false)
	// Generate UUID for main index entry
	uUIDTmp, err := uuid.NewV7()
	if err != nil {
		return "", nil
	}
	uUID := uUIDTmp.String()
	err = db.doInsert(mod, []byte(uUID), data, indicesClean, false)
	if err != nil {
		return "", err
	}
	return uUID, nil
}

// SInsert adds an entry to the database without creating a UUID
func (db *GoDB) SInsert(
	mod string, data []byte, indices map[string]string,
) error {
	indicesClean, _ := db.validateIndices(indices, false)
	err := db.doInsert(mod, []byte(""), data, indicesClean, true)
	if err != nil {
		return err
	}
	return nil
}

// Update overrides an existing entry and its sub-indices if provided
func (db *GoDB) Update(
	mod string, txn *badger.Txn, uUID string, data []byte, indices map[string]string,
) error {
	indicesClean, _ := db.validateIndices(indices, false)
	err := db.doUpdate(mod, txn, []byte(uUID), data, indicesClean, false)
	if err != nil {
		return err
	}
	return nil
}

// SUpdate overrides an existing entry and its sub-indices without a UUID
//
// Can (and should) be used for custom indices which do not have their own UUID
func (db *GoDB) SUpdate(
	mod string, txn *badger.Txn, data []byte, indices map[string]string,
) error {
	indicesClean, _ := db.validateIndices(indices, false)
	err := db.doUpdate(mod, txn, []byte(""), data, indicesClean, false)
	if err != nil {
		return err
	}
	return nil
}

// Delete removes an entry from the database
func (db *GoDB) Delete(mod string, uUID string, indices []string) error {
	if uUID == "" {
		return errors.New("missing uuid")
	}
	bUUID := []byte(uUID)
	err := db.db.Update(func(txn *badger.Txn) error {
		// Delete main index entry
		err := txn.Delete([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)))
		if err != nil {
			return err
		}
		// Delete sub index entries
		for _, k := range indices {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			opts.Reverse = true
			it := txn.NewIterator(opts)
			prefix := []byte(fmt.Sprintf("%s:%s:", mod, k))
			for SeekLast(it, prefix); it.ValidForPrefix(prefix); it.Next() {
				// Match!
				item := it.Item()
				_ = item.Value(func(val []byte) error {
					if bytes.Equal(val, bUUID) {
						_ = txn.Delete(item.KeyCopy(nil))
					}
					return nil
				})
			}
			it.Close()
		}
		return nil
	})
	return err
}

// Get retrieves a main index entry with the provided UUID and returns it with a transaction
func (db *GoDB) Get(mod, uUID string) (*EntryResponse, *badger.Txn) {
	var ixEntry []byte
	err := db.db.View(func(txn *badger.Txn) error {
		// Get main index entry
		ix, err := txn.Get([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)))
		if err != nil {
			return err
		}
		ixEntry, err = ix.ValueCopy(nil)
		return nil
	})
	if err != nil || len(ixEntry) < 1 {
		return nil, nil
	}
	entryResponse := &EntryResponse{
		uUID: uUID,
		Data: ixEntry,
	}
	return entryResponse, db.db.NewTransaction(true)
}

// Read retrieves a main index entry with the provided UUID and returns it
func (db *GoDB) Read(mod, uUID string) (*EntryResponse, bool) {
	var ixEntry []byte
	err := db.db.View(func(txn *badger.Txn) error {
		// Get main index entry
		ix, err := txn.Get([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)))
		if err != nil {
			return err
		}
		ixEntry, err = ix.ValueCopy(nil)
		return nil
	})
	if err != nil || len(ixEntry) < 1 {
		return nil, false
	}
	entryResponse := &EntryResponse{
		uUID: uUID,
		Data: ixEntry,
	}
	return entryResponse, true
}

// Select searches, batches up and returns all entries from the database with the provided filters
func (db *GoDB) Select(
	mod string, indices map[string]string, options *SelectOptions,
) (chan []*EntryResponse, error) {
	indicesClean, err := db.validateIndices(indices, true)
	if err != nil {
		return nil, err
	}
	// Set default SelectOptions
	maxResults := int64(-1)
	page := int64(0)
	skip := int64(0)
	// Check *SelectOptions
	if options != nil {
		maxResults = options.MaxResults
		page = options.Page
		skip = options.Skip
	}
	// Return if no results are wanted (probably malformed input)
	if maxResults == 0 {
		return nil, nil
	}
	hasMaxResults := maxResults != int64(-1)
	// Calculate final skip count if page is not the first one + maxResults is set
	if page > int64(0) && maxResults != int64(-1) {
		// Skip an additional maxResults * page results
		skip += maxResults * page
	}
	// Prepare wait group and response channels
	wg := sync.WaitGroup{}
	responsesInternal := make(chan *EntryResponse)
	responsesExternal := make(chan []*EntryResponse)
	done := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	// Launch index search goroutines
	for key, value := range indicesClean {
		wg.Add(1)
		valueT := value
		keyT := key
		go func() {
			defer func() {
				if r := recover(); r != nil {
					return
				}
			}()
			db.singleIndexQuery(mod, processArrayIndexKey(keyT), valueT, responsesInternal, &wg, ctx, true, false)
		}()
	}
	// Start goroutine awaiting a cancellation
	go func() {
		wg.Wait()
		done <- true
	}()
	// Start goroutine collecting all results
	go func() {
		sortedEntries := make([]*EntryResponse, 0)
		count := &atomic.Int64{}
		attempts := &atomic.Int64{}
		current := int64(0)
		skipDone := skip == int64(0) // If skip = 0, skipDone is automatically true
		gatherDone := false
		cache := map[string]bool{} // Unique results only
		for {
			select {
			case <-done:
				// *** We are done collecting ***
				close(responsesInternal)
				// Sort by uuid V7 to ensure order of returned values
				sort.SliceStable(
					sortedEntries, func(i, j int) bool {
						return sortedEntries[i].uUID > sortedEntries[j].uUID
					},
				)
				// Send back to receiver
				responsesExternal <- sortedEntries
				close(responsesExternal)
				return
			case entry := <-responsesInternal:
				// *** New result collected ***
				if entry.uUID == "" {
					continue
				}
				if gatherDone {
					break
				}
				// Only collect unique results, so check cache first
				if cache[entry.uUID] {
					continue
				} else {
					// Not found yet, so remember it now
					cache[entry.uUID] = true
				}
				// Collect all found values after having skipped all results that had to be skipped
				if skipDone || attempts.Load() >= skip {
					// Append the result to the slice
					sortedEntries = append(sortedEntries, entry)
					if hasMaxResults {
						current = count.Add(1)
						// Check if we've reached the maximum results
						if current >= maxResults {
							cancel()
							gatherDone = true
						}
					}
				} else {
					attempts.Add(1)
				}
				break
			}
		}
	}()
	// Return response channel
	return responsesExternal, nil
}

// SSelect searches and returns entries one by one from the database with the provided filters.
//
// Since there could be millions of items, a timeout (adjusted with timeoutSec)
// in seconds is required to avoid searching forever.
//
// An unbuffered or low capacity response channel (adjusted with bufSize) paired with a low timeout
// could lead to missing more responses as the timeout does not pause upon processing results.
//
// When using getEntry=false, only UUIDs will be returned. This speeds up the query allowing for counting.
func (db *GoDB) SSelect(
	mod string, indices map[string]string, options *SelectOptions, timeoutSec int, bufSize int, getEntry, omitUID bool,
) (chan *EntryResponse, context.CancelFunc, error) {
	indicesClean, err := db.validateIndices(indices, true)
	if err != nil {
		return nil, nil, err
	}
	// Set default SelectOptions
	maxResults := int64(-1)
	page := int64(0)
	skip := int64(0)
	// Check *SelectOptions
	if options != nil {
		maxResults = options.MaxResults
		page = options.Page
		skip = options.Skip
	}
	if timeoutSec < 0 {
		timeoutSec = 999999
	}
	if bufSize < 0 {
		bufSize = 0
	}
	// Return if no results are wanted (probably malformed input)
	if maxResults == 0 {
		return nil, nil, nil
	}
	hasMaxResults := maxResults != int64(-1)
	// Calculate final skip count if page is not the first one + maxResults is set
	if page > int64(0) && maxResults != int64(-1) {
		// Skip an additional maxResults * page results
		skip += maxResults * page
	}
	// Prepare wait group and response channels
	wg := sync.WaitGroup{}
	responsesInternal := make(chan *EntryResponse)
	responsesExternal := make(chan *EntryResponse, bufSize)
	done := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	// Launch index search goroutines
	for key, value := range indicesClean {
		wg.Add(1)
		valueT := value
		keyT := key
		go func() {
			defer func() {
				if r := recover(); r != nil {
					return
				}
			}()
			db.singleIndexQuery(mod, processArrayIndexKey(keyT), valueT, responsesInternal, &wg, ctx, getEntry, omitUID)
		}()
	}
	// Start goroutine awaiting a cancellation
	go func() {
		wg.Wait()
		done <- true
	}()
	// Start goroutine collecting all results
	go func() {
		count := &atomic.Int64{}
		attempts := &atomic.Int64{}
		current := int64(0)
		gatherDone := false
		skipDone := skip == int64(0)                                   // If skip = 0, skipDone is automatically true
		cache := map[string]bool{}                                     // Unique results only
		timeout := time.After(time.Duration(timeoutSec) * time.Second) // Added to avoid deadlock situations (1 GB RAM server moments)
		for {
			select {
			case <-timeout:
				// *** Timeout ***
				cancel()
				close(responsesInternal)
				close(responsesExternal)
				return
			case <-done:
				// *** We are done collecting ***
				close(responsesInternal)
				close(responsesExternal)
				return
			case entry := <-responsesInternal:
				// *** New result collected ***
				if entry.uUID == "" {
					continue
				}
				if gatherDone {
					break
				}
				// Only collect unique results, so check cache first
				if cache[entry.uUID] {
					continue
				} else {
					// Not found yet, so remember it now
					cache[entry.uUID] = true
				}
				// Collect all found values after having skipped all results that had to be skipped
				if skipDone || attempts.Load() >= skip {
					// Send back to caller
					responsesExternal <- entry
					if hasMaxResults {
						current = count.Add(1)
						// Check if we've reached the maximum results
						if current >= maxResults {
							cancel()
							gatherDone = true
						}
					}
				} else {
					attempts.Add(1)
				}
				break
			}
		}
	}()
	// Return response channel
	return responsesExternal, cancel, nil
}

// MassSearch uses badger.Stream to split one big DB query into many smaller ones.
// This function is useful for querying the biggest databases.
func (db *GoDB) MassSearch(
	mod, prefix, value, field string, query []string, maxLength, bufSize int, ctx context.Context,
) chan *MassEntryResponse {
	if mod == "" || prefix == "" || value == "" {
		return nil
	}
	if len(query) == 0 {
		return nil
	}
	var ix *badger.Item
	var ixEntry []byte
	var start int
	var end int
	var bField []byte
	var hadFirst bool
	var hadBSlash bool
	var b byte
	// Special characters we will be looking for.
	// Since they are single-byte (e.g. " simply is 34) we just use index 0
	BSlash := []byte("\\")[0]
	Delim := []byte("\"")[0]
	hasField := len(field) > 0
	if hasField {
		// Fields are json fields, so we need to query those as such
		bField = []byte(fmt.Sprintf("\"%s\":", field))
	} else {
		bField = make([]byte, 0)
	}
	// Convert query words into slice of byte slices
	bQuery := make([][]byte, len(query))
	for i := 0; i < len(query); i++ {
		bQuery[i] = bytes.ToLower([]byte(query[i]))
	}
	ival := fmt.Sprintf("%s:%s:%s", mod, prefix, FIndex(value))
	count := &atomic.Int64{}
	if bufSize < 0 {
		bufSize = 0
	}
	responsesExternal := make(chan *MassEntryResponse, bufSize)
	// Prepare stream
	cache := map[string]bool{}
	stream := db.db.NewStream()
	stream.NumGo = 2 // TODO: Make this system dependant (e.g. check CPUs)
	stream.Prefix = []byte(ival)
	stream.ChooseKey = nil // We want them all!
	stream.KeyToList = nil // Regular KeyToList
	stream.Send = func(buf *z.Buffer) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		list, err := badger.BufferToKVList(buf)
		if err != nil {
			return err
		}
		txn := db.NewTransaction(false)
		defer txn.Discard()
		for _, kv := range list.Kv {
			if kv.StreamDone == true {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			// Only collect unique results, so check cache first
			if cache[string(kv.Value)] {
				continue
			} else {
				// Not found yet, so remember it now
				cache[string(kv.Value)] = true
			}
			ix, err = txn.Get([]byte(fmt.Sprintf("%s:uid:%s", mod, kv.Value)))
			if err != nil {
				continue
			}
			ixEntry, err = ix.ValueCopy(nil)
			if err != nil || len(ixEntry) == 0 {
				continue
			}
			// We may now apply filters to this entry
			// Boundaries are defined by a field (optional, marks the beginning) and length
			if hasField {
				start = bytes.Index(ixEntry, bField)
				if start == -1 {
					// Entry did not contain the field at all
					continue
				}
				// Start searching after the field
				start += len(bField)
			} else {
				// Start searching right away
				start = 0
			}
			// Limit the amount of text to be queried
			if maxLength > 0 && maxLength < len(ixEntry) {
				ixEntry = ixEntry[start:maxLength]
			} else {
				ixEntry = ixEntry[start:]
			}
			// Check if we would query more than the field targeted
			// Example:
			//    1. Field: 'a' Query 'value' Entry {"a":"value","b":"value"}
			//
			//    After finding field 'a' at index 2, we need to check boundaries for this field
			//    ...to avoid entering field 'b'
			//    To achieve this, we simply iterate over the bytes until we have reached the end of the json field
			//    ...indicated by an unescaped " character
			hadFirst = false
			hadBSlash = false
			end = -1
			start = 0
			for i := 0; i < len(ixEntry); i++ {
				if hadBSlash {
					// Backslash escapes the following (this) character
					// ...so we simply ignore this one without having to look at it
					hadBSlash = false
					continue
				}
				b = ixEntry[i]
				// Look for special characters, e.g. delimiter
				switch b {
				case BSlash:
					hadBSlash = true
					continue
				case Delim:
					if !hadFirst {
						// Ignore start of field for now
						hadFirst = true
						// Also, later splice away the beginning of the field
						start = i + 1
					} else {
						// End of field reached
						end = i
						break
					}
				}
				if end > -1 {
					break
				}
			}
			if end > -1 {
				ixEntry = ixEntry[start:end]
			} else if start > 0 {
				ixEntry = ixEntry[start:]
			}
			// We now have the text inside our targeted field
			// Now, we will look for the amount of matches for each query word provided
			results := CountByteSliceMatches(bytes.ToLower(ixEntry), bQuery)
			if len(results) == 0 {
				continue
			}
			c := 0
			for _, result := range results {
				c += len(result)
			}
			if c == 0 {
				continue
			}
			// Get a fresh copy again since we sliced and diced the other one...
			ixEntry, err = ix.ValueCopy(nil)
			if err != nil {
				continue
			}
			responsesExternal <- &MassEntryResponse{
				uUID:   string(kv.Value),
				Data:   ixEntry,
				Counts: results,
			}
			count.Add(1)
		}
		return nil
	}
	// Start stream
	go func() {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		_ = stream.Orchestrate(ctx)
		// *** We are done collecting ***
		close(responsesExternal)
	}()
	// Results will be sent back right away, so return the output channel
	return responsesExternal
}

// NewTransaction returns a BadgerDB Transaction for read (update=false) or write (update=true) purposes.
// When updating entries using new data without checking its previous value
// ...(basically forcefully overwriting the old value) it is faster to just generate a new transaction
// ...without retrieving the old entry from disk.
func (db *GoDB) NewTransaction(update bool) *badger.Txn {
	return db.db.NewTransaction(update)
}

// SearchInBytes directly queries the bytes of an entry retrieved from the DB.
// If works by looking for the json field provided, trimming the text from its start to either the end of it or
// ...until maxLength has been reached. It knows that escaping is, so \" is not detected as the end of the field.
func SearchInBytes(ixEntry []byte, field string, query []string, maxLength int) *MassEntryResponse {
	if len(ixEntry) == 0 || len(query) == 0 {
		return nil
	}
	var bField []byte
	if len(field) > 0 {
		// Fields are json fields, so we need to query those as such
		bField = []byte(fmt.Sprintf("\"%s\":", field))
	} else {
		bField = make([]byte, 0)
	}
	// Convert query words into slice of byte slices
	bQuery := make([][]byte, len(query))
	for i := 0; i < len(query); i++ {
		bQuery[i] = bytes.ToLower([]byte(query[i]))
	}
	// We may now apply filters to this entry
	ixEntry = GetByteValueFromField(ixEntry, bField, maxLength)
	// We now have the text inside our targeted field
	// Now, we will look for the amount of matches for each query word provided
	results := CountByteSliceMatches(bytes.ToLower(ixEntry), bQuery)
	if len(results) == 0 {
		return nil
	}
	c := 0
	for _, result := range results {
		c += len(result)
	}
	if c == 0 {
		return nil
	}
	return &MassEntryResponse{
		Counts: results,
	}
}

// ### Internal ###

func (db *GoDB) doInsert(
	mod string, uUID []byte, data []byte, indices map[string]string, omitUID bool,
) error {
	err := db.db.Update(func(txn *badger.Txn) error {
		var err error
		if !omitUID {
			// Create main index entry
			err = txn.Set([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)), data)
			if err != nil {
				return err
			}
		}
		// Create sub index entries (using the provided indices)
		// The whole purpose of sub index entries is to point to the main index entry
		// E.G.: (DB: UserDB = m1; IX: Username = usr)
		//				   	|      Index          |        Data        |
		//            | ------------------- | ------------------ |
		// 		Main:	 	|	m1:uid:12345		    |	User1, Sample Name |
		// 		Sub:		|	m1:usr:User1;12345	|	12345							 |
		var ival string
		for k, v := range indices {
			ival = fmt.Sprintf("%s:%s:%s;%s", mod, processArrayIndexKey(k), v, uUID)
			if omitUID {
				// Custom indices do not point to uuids since they have their own data, instead
				err = txn.Set([]byte(ival), data)
			} else {
				err = txn.Set([]byte(ival), uUID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (db *GoDB) doUpdate(
	mod string, txn *badger.Txn, uUID []byte, data []byte, indices map[string]string, omitUID bool,
) error {
	defer txn.Discard()
	var err error
	if !omitUID {
		// Create main index entry
		err = txn.Set([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)), data)
		if err != nil {
			return err
		}
	}
	// Create sub index entries (using the provided indices)
	// The whole purpose of sub index entries is to point to the main index entry
	// E.G.: (DB: UserDB = m1; IX: Username = usr)
	//				   	|      Index         |        Data        |
	//            | ------------------ | ------------------ |
	// 		Main:	 	|	m1:uid:12345       | User1, Sample Name |
	// 		Sub:		|	m1:usr:User1;12345 | 12345              |
	var ival string
	// Since we can process array indices, we need to make sure
	// ...not to delete indices more than once later on
	delCache := make(map[string]bool)
	for k, v := range indices {
		// Remove array index values
		k = processArrayIndexKey(k)
		// Delete existing indices once
		if !delCache[k] {
			delCache[k] = true
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			opts.Reverse = true
			it := txn.NewIterator(opts)
			ival = fmt.Sprintf("%s:%s:", mod, k)
			prefix := []byte(ival)
			for SeekLast(it, prefix); it.ValidForPrefix(prefix); it.Next() {
				// Match!
				item := it.Item()
				_ = item.Value(func(val []byte) error {
					if omitUID || bytes.Equal(val, uUID) {
						_ = txn.Delete(item.KeyCopy(nil))
					}
					return nil
				})
			}
			it.Close()
		}
		// Set new index
		if v == "" {
			// Skip empty values as their keys are only needed to clear old entries
			continue
		}
		ival = fmt.Sprintf("%s:%s:%s;%s", mod, k, v, uUID)
		err = txn.Set([]byte(ival), uUID)
		if err != nil {
			return err
		}
	}
	err = txn.Commit()
	return err
}

func (db *GoDB) singleIndexQuery(
	mod, index, value string, responses chan *EntryResponse, wg *sync.WaitGroup, ctx context.Context, getEntry, omitUID bool,
) {
	defer wg.Done()
	noResults := true
	// Prefix Iteration
	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		ival := fmt.Sprintf("%s:%s:%s", mod, index, value)
		prefix := []byte(ival)
		var ix *badger.Item
		var err error
		var item *badger.Item
		var ixEntry []byte
		for SeekLast(it, prefix); it.ValidForPrefix(prefix); it.Next() {
			// Listen to the Done-chanel to make sure we're not wasting resources
			select {
			case <-ctx.Done():
				return errors.New("CTX cancel received")
			default:
			}
			// Match!
			item = it.Item()
			err = item.Value(func(v []byte) error {
				if omitUID {
					// Custom index, so we will just return the key and value as is
					noResults = false
					responses <- &EntryResponse{
						uUID: string(item.KeyCopy(nil)),
						Data: bytes.Clone(v),
					}
				} else {
					if getEntry {
						// Since sub index entries' values point to the main index entry's uuid,
						// we need to get the main index entry now
						ix, err = txn.Get([]byte(fmt.Sprintf("%s:uid:%s", mod, v)))
						if err != nil {
							return nil
						}
						ixEntry, err = ix.ValueCopy(nil)
						if err != nil {
							return nil
						}
						noResults = false
						responses <- &EntryResponse{
							uUID: string(v),
							Data: ixEntry,
						}
					} else {
						noResults = false
						responses <- &EntryResponse{
							uUID: string(bytes.Clone(v)),
							Data: nil,
						}
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return
	}
	if noResults {
		responses <- &EntryResponse{
			uUID: "",
			Data: nil,
		}
	}
}

// ### Utility ###

func (db *GoDB) validateIndices(indices map[string]string, isSelect bool) (map[string]string, error) {
	indicesClean := make(map[string]string)
	for key, value := range indices {
		// Skip uid unless we're selecting
		if key == "uid" && !isSelect {
			continue
		}
		// Check if index value exceeds maximum
		if len(value) > db.DBSettings.ixMaxLength {
			// Shorten it to the desired length
			value = value[0:db.DBSettings.ixMaxLength]
		}
		indicesClean[key] = value
	}
	if isSelect && len(indicesClean) < 1 {
		return nil, errors.New("no valid index queries provided")
	}
	return indicesClean, nil
}

func processArrayIndexKey(key string) string {
	// We will remove array index values from keys
	// E.g. turning "cat[1" (the character "]" is omitted) to "cat"
	return strings.Split(key, "[")[0]
}

func incrementPrefix(prefix []byte) []byte {
	result := make([]byte, len(prefix))
	copy(result, prefix)
	var l = len(prefix)
	for l > 0 {
		if result[l-1] == 0xFF {
			l -= 1
		} else {
			result[l-1] += 1
			break
		}
	}
	return result[0:l]
}

// CountByteSliceMatches takes a list of byte arrays and matches ixEntry for all of them
// It returns a map of the words indices and their positions in ixEntry
func CountByteSliceMatches(ixEntry []byte, words [][]byte) map[int][]int {
	counts := make(map[int][]int)
	for i, wrd := range words {
		searchData := ixEntry
		for j, k := bytes.Index(searchData, wrd), 0; j > -1; j, k = bytes.Index(searchData, wrd), k+j+1 {
			counts[i] = append(counts[i], j+k)
			searchData = searchData[j+1:]
		}
	}
	return counts
}

func GetByteValueFromField(ixEntry, field []byte, maxLength int) []byte {
	var start int
	var end int
	var hadFirst bool
	var hadBSlash bool
	var b byte
	// Special characters we will be looking for.
	// Since they are single-byte (e.g. " simply is 34) we just use index 0
	BSlash := []byte("\\")[0]
	Delim := []byte("\"")[0]
	// Boundaries are defined by a field (optional, marks the beginning) and length
	if len(field) > 0 {
		start = bytes.Index(ixEntry, field)
		if start == -1 {
			// Entry did not contain the field at all
			return nil
		}
		// Start searching after the field
		start += len(field)
	} else {
		// Start searching right away
		start = 0
	}
	// Limit the amount of text to be queried
	if maxLength > 0 && start+maxLength < len(ixEntry) {
		ixEntry = ixEntry[start : start+maxLength]
	} else {
		ixEntry = ixEntry[start:]
	}
	// Check if we would query more than the field targeted
	// Example:
	//    1. Field: 'a' Query 'value' Entry {"a":"value","b":"value"}
	//
	//    After finding field 'a' at index 2, we need to check boundaries for this field
	//    ...to avoid entering field 'b'
	//    To achieve this, we simply iterate over the bytes until we have reached the end of the json field
	//    ...indicated by an unescaped " character
	hadFirst = false
	hadBSlash = false
	end = -1
	start = 0
	for i := 0; i < len(ixEntry); i++ {
		if hadBSlash {
			// Backslash escapes the following (this) character
			// ...so we simply ignore this one without having to look at it
			hadBSlash = false
			continue
		}
		b = ixEntry[i]
		// Look for special characters, e.g. delimiter
		switch b {
		case BSlash:
			hadBSlash = true
			continue
		case Delim:
			if !hadFirst {
				// Ignore start of field for now
				hadFirst = true
				// Also, later splice away the beginning of the field
				start = i + 1
			} else {
				// End of field reached
				end = i
				break
			}
		}
		if end > -1 {
			break
		}
	}
	if end > -1 {
		ixEntry = ixEntry[start:end]
	} else if start > 0 {
		ixEntry = ixEntry[start:]
	}
	return ixEntry
}

func SeekLast(it *badger.Iterator, prefix []byte) {
	i := incrementPrefix(prefix)
	it.Seek(i)
	if it.Valid() && bytes.Equal(i, it.Item().Key()) {
		it.Next()
	}
}

func checkModuleDir(module string, workDir string) string {
	err := os.Mkdir(filepath.Join(workDir, "db"), 0755)
	if err != nil && !os.IsExist(err) {
		return ""
	}
	dbPath := filepath.Join(workDir, "db", module)
	err = os.Mkdir(dbPath, 0755)
	if err != nil && !os.IsExist(err) {
		return ""
	}
	return dbPath
}
