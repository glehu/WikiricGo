package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
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
	err = db.doInsert(mod, []byte(uUID), data, indicesClean)
	if err != nil {
		return "", err
	}
	return uUID, nil
}

// Update overrides an existing entry and its sub-indices if provided
func (db *GoDB) Update(
	mod string, txn *badger.Txn, uUID string, data []byte, indices map[string]string,
) error {
	indicesClean, _ := db.validateIndices(indices, false)
	err := db.doUpdate(mod, txn, []byte(uUID), data, indicesClean)
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

func (db *GoDB) Read(mod, uUID string) (*EntryResponse, bool) {
	var ixEntry []byte
	err := db.db.View(func(txn *badger.Txn) error {
		// Delete main index entry
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
			db.singleIndexQuery(mod, processArrayIndexKey(keyT), valueT, responsesInternal, &wg, ctx)
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
func (db *GoDB) SSelect(
	mod string, indices map[string]string, options *SelectOptions, timeoutSec int, bufSize int,
) (chan *EntryResponse, error) {
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
	if timeoutSec < 0 {
		timeoutSec = 999999
	}
	if bufSize < 0 {
		bufSize = 0
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
			db.singleIndexQuery(mod, processArrayIndexKey(keyT), valueT, responsesInternal, &wg, ctx)
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
	return responsesExternal, nil
}

func (db *GoDB) doInsert(
	mod string, uUID []byte, data []byte, indices map[string]string,
) error {
	err := db.db.Update(func(txn *badger.Txn) error {
		// Create main index entry
		err := txn.Set([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)), data)
		if err != nil {
			return err
		}
		// Create sub index entries (using the provided indices)
		// The whole purpose of sub index entries is to point to the main index entry
		// E.G.: (DB: UserDB = m1; IX: Username = usr)
		//				   	|      Index          |        Data        |
		//            | ------------------- | ------------------ |
		// 		Main:	 	|	m1:12345				    |	User1, Sample Name |
		// 		Sub:		|	m1:usr:User1;12345	|	12345							 |
		var ival string
		for k, v := range indices {
			ival = fmt.Sprintf("%s:%s:%s;%s", mod, processArrayIndexKey(k), v, uUID)
			err = txn.Set([]byte(ival), uUID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (db *GoDB) doUpdate(
	mod string, txn *badger.Txn, uUID []byte, data []byte, indices map[string]string,
) error {
	defer txn.Discard()
	// Create main index entry
	err := txn.Set([]byte(fmt.Sprintf("%s:uid:%s", mod, uUID)), data)
	if err != nil {
		return err
	}
	// Create sub index entries (using the provided indices)
	// The whole purpose of sub index entries is to point to the main index entry
	// E.G.: (DB: UserDB = m1; IX: Username = usr)
	//				   	|      Index         |        Data        |
	//            | ------------------ | ------------------ |
	// 		Main:	 	|	m1:12345           | User1, Sample Name |
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
					if bytes.Equal(val, uUID) {
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
	mod, index, value string, responses chan *EntryResponse, wg *sync.WaitGroup, ctx context.Context,
) {
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
				wg.Done()
				return errors.New("CTX cancel received")
			default:
			}
			// Match!
			item = it.Item()
			err = item.Value(func(v []byte) error {
				// Since sub index entries' values point to the main index entry's uuid,
				// we need to get the main index entry now
				ix, err = txn.Get([]byte(fmt.Sprintf("%s:uid:%s", mod, v)))
				if err != nil {
					return nil
				}
				ixEntry, err = ix.ValueCopy(nil)
				noResults = false
				responses <- &EntryResponse{
					uUID: string(v),
					Data: ixEntry,
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
	wg.Done()
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
