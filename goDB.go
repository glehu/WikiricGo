package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/tidwall/btree"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ### CONST ###

const defaultIxCapacity = 2_000_000
const defaultIxValueMaxLength = 100

// ### TYPES ###

type EntryResponse struct {
	uUID  string
	Index *Index
	Data  []byte
}

// Index points to a database entry and is being contained by a named IndexMap
type Index struct {
	value string
	pos   int64
	len   int64
}

// IndexMap is a named index map containing Index elements and a pointer to its *os.File
type IndexMap struct {
	index       *btree.Map[string, *Index]
	ixFile      *os.File
	ixFileMutex *sync.RWMutex
}

type DBSettings struct {
	ixCapacity  int64
	ixMaxLength int
}

type IXChannelCommand struct {
	index      string
	uUID       string
	indexEntry *Index
}

type GoDB struct {
	dbFile    *os.File
	workDir   string
	module    string
	indices   map[string]IndexMap
	dbMutex   *sync.RWMutex
	ixMutex   *sync.RWMutex
	ixChannel chan *IXChannelCommand
	DBSettings
}

type SelectOptions struct {
	MaxResults int64
	Page       int64
	Skip       int64
}

// DB Interface
type DB interface {
	// Storage Methods

	Insert(data []byte, indices map[string]string) error
	Update(uUID string, data []byte, indices map[string]string) error
	Delete(uUID string) error
	Get(uUID string) (*EntryResponse, bool)
	Select(indices map[string]string) (chan *EntryResponse, error)

	// Utility Methods

	// CloseDB closes the database file
	CloseDB() error

	// Internal Methods

	checkIXFile(index string, level int32) error
	writeIXCache(index string, uUID uuid.UUID, indexEntry *Index) error
	singleIndexQuery(index, query *regexp.Regexp, responses chan *EntryResponse, wg *sync.WaitGroup)
	readFromDB(pos int64, len int64) ([]byte, error)
}

// OpenDB creates a named database (e.g. users), initialized with the provided named indices (e.g. username)
func OpenDB(module string, indices []string) *GoDB {
	// Set working directory
	workDirTmp, _ := os.Getwd()
	checkModuleDir(module, workDirTmp)
	// Create DB file if missing
	databaseFilename, err := checkDBFile(module, workDirTmp)
	if err != nil {
		log.Panic("err during db file check:", err)
	}
	// Set file pointer
	dbFileTmp, err := os.OpenFile(databaseFilename, os.O_RDWR, 0644)
	if err != nil {
		log.Panic("err during db file open:", err)
	}
	// Create db struct pointer and return
	ixChannelTmp := make(chan *IXChannelCommand, 1_000)
	goDB := &GoDB{
		dbFile:    dbFileTmp,
		workDir:   workDirTmp,
		module:    module,
		indices:   make(map[string]IndexMap),
		dbMutex:   &sync.RWMutex{},
		ixMutex:   &sync.RWMutex{},
		ixChannel: ixChannelTmp,
		DBSettings: DBSettings{
			ixCapacity:  defaultIxCapacity,
			ixMaxLength: defaultIxValueMaxLength,
		},
	}
	// Check base index (uuid)
	err = goDB.checkIXFile("uuid", 0)
	if err != nil {
		log.Panic("err during base ix file check", err)
	}
	// Check custom index files
	for _, indexName := range indices {
		if indexName == "uuid" {
			continue
		}
		err = goDB.checkIXFile(indexName, 0)
		if err != nil {
			log.Panic("err during custom ix file check", err)
		}
	}
	go startIXFileWorker(goDB, ixChannelTmp)
	return goDB
}

func startIXFileWorker(goDB *GoDB, jobs <-chan *IXChannelCommand) {
	for job := range jobs {
		err := goDB.writeIXCache(job.index, job.uUID, job.indexEntry)
		if err != nil {
			log.Panic("ix cache write fail:", err)
		}
	}
}

// ### DB Functions ###

// Insert adds an entry to the database
func (db *GoDB) Insert(data []byte, indices map[string]string) (string, error) {
	indicesClean, _ := db.validateIndices(indices, false)
	// Generate UUID
	uUIDTmp, err := uuid.NewV7()
	if err != nil {
		log.Panic("err generating uuid", err)
	}
	uUID := uUIDTmp.String()
	err = db.doInsert(uUID, data, indicesClean)
	return uUID, err
}

func (db *GoDB) doInsert(uUID string, data []byte, indices map[string]string) error {
	// MUTEX LOCK
	db.dbMutex.Lock()
	// Find end of file position
	stat, err := db.dbFile.Stat()
	if err != nil {
		return errors.New("db file stat failed")
	}
	offset := stat.Size()
	// Write bytes
	_, err = db.dbFile.WriteAt(data, offset)
	// MUTEX UNLOCK
	db.dbMutex.Unlock()
	if err != nil {
		return errors.New("db write failed")
	}
	db.writeIndices(uUID, offset, int64(len(data)), indices)
	return nil
}

// Delete removes an entry from the database
func (db *GoDB) Delete(uUID string) error {
	// Lock the entry
	_ = db.Lock(uUID)
	prevIndex, ok := db.indices["uuid"].index.Get(uUID)
	if !ok {
		return nil
	}
	emptyBytes := make([]byte, prevIndex.len)
	// MUTEX LOCK
	db.dbMutex.Lock()
	// Write bytes
	_, err := db.dbFile.WriteAt(emptyBytes, prevIndex.pos)
	// MUTEX UNLOCK
	db.dbMutex.Unlock()
	if err != nil {
		return errors.New("db write failed")
	}
	var indexEntry *Index
	for key, index := range db.indices {
		indexEntry = &Index{
			value: "",
			pos:   -1,
			len:   -1,
		}
		db.ixChannel <- &IXChannelCommand{
			index:      key,
			uUID:       uUID,
			indexEntry: indexEntry,
		}
		index.index.Delete(uUID)
	}
	return nil
}

// Update changes an entry in the database
func (db *GoDB) Update(uUID string, data []byte, indices map[string]string) error {
	indicesClean, err := db.validateIndices(indices, false)
	if err != nil {
		return err
	}
	length := int64(len(data))
	// Check if new data is smaller or same size as current data
	// If this is true, then offset will not change,
	// otherwise we will have to append the new data to the end of the file
	prevIndex, ok := db.indices["uuid"].index.Get(uUID)
	if !ok {
		prevIndex = &Index{
			value: "",
			pos:   -1,
			len:   -1,
		}
	}
	if length > prevIndex.len {
		// Length exceeded -> Delete, then append to end with same uUID
		err = db.Delete(uUID)
		if err != nil {
			return err
		}
		err = db.doInsert(uUID, data, indicesClean)
		if err != nil {
			return err
		}
		return nil
	}
	// ELSE: Length smaller or same -> Override
	// MUTEX LOCK
	db.dbMutex.Lock()
	offset := prevIndex.pos
	// Write bytes
	_, err = db.dbFile.WriteAt(data, offset)
	// MUTEX UNLOCK
	db.dbMutex.Unlock()
	if err != nil {
		return errors.New("db write failed")
	}
	db.writeIndices(uUID, offset, length, indicesClean)
	return nil
}

// Lock prevents others to get writing access to a single entry
func (db *GoDB) Lock(uUID string) (lid string) {
	lck, _ := uuid.NewV7()
	lid = lck.String()
	for {
		ok := db.doLock(uUID, lid)
		if ok {
			break
		} else {
			ticker := time.NewTicker(time.Millisecond * 15)
			<-ticker.C
			ticker.Stop()
		}
	}
	return lid
}

func (db *GoDB) doLock(uUID, username string) bool {
	db.ixMutex.Lock()
	defer db.ixMutex.Unlock()
	index, ok := db.indices["uuid"].index.Get(uUID)
	if !ok {
		return true
	}
	// Only lock if nobody else locked it
	if index.value == "" {
		index.value = username
		db.indices["uuid"].index.Set(uUID, index)
		return true
	}
	return false
}

func (db *GoDB) Unlock(uUID, lid string) bool {
	db.ixMutex.Lock()
	defer db.ixMutex.Unlock()
	index, ok := db.indices["uuid"].index.Get(uUID)
	if !ok {
		return true
	}
	if index.value == "" {
		return true
	}
	if index.value == lid {
		index.value = ""
		db.indices["uuid"].index.Set(uUID, index)
		return true
	}
	return false
}

func (db *GoDB) Get(uUID string) (*EntryResponse, string) {
	index, ok := db.indices["uuid"].index.Get(uUID)
	if !ok {
		return nil, ""
	}
	// Lock the entry
	lid := db.Lock(uUID)
	content, err := db.readFromDB(index.pos, index.len)
	if err != nil {
		return nil, ""
	}
	entryResponse := &EntryResponse{
		uUID:  uUID,
		Index: index,
		Data:  content,
	}
	return entryResponse, lid
}

// Select returns entries from the database
func (db *GoDB) Select(indices map[string]string, options *SelectOptions) (chan []*EntryResponse, error) {
	indicesClean, err := db.validateIndices(indices, true)
	if err != nil {
		return nil, err
	}
	// Check *SelectOptions
	maxResults := int64(-1)
	page := int64(0)
	skip := int64(0)
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
	// Return if all results had been skipped (probably malformed input)
	if skip >= int64(db.indices["uuid"].index.Len()) {
		return nil, nil
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
		query, err := regexp.Compile(value)
		if err == nil {
			go db.singleIndexQuery(key, query, responsesInternal, &wg, ctx)
		}
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
		for {
			select {
			case <-done:
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
				if gatherDone {
					break
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

func (db *GoDB) validateIndices(indices map[string]string, isSelect bool) (map[string]string, error) {
	indicesClean := make(map[string]string)
	for key, value := range indices {
		// Skip uuid unless we're selecting
		if key == "uuid" && !isSelect {
			continue
		}
		if _, present := db.indices[key]; present {
			indicesClean[key] = value
		}
	}
	if isSelect && len(indicesClean) < 1 {
		return nil, errors.New("no valid index queries provided")
	}
	return indicesClean, nil
}

func (db *GoDB) singleIndexQuery(
	index string, query *regexp.Regexp, responses chan *EntryResponse, wg *sync.WaitGroup, ctx context.Context,
) {
	// MUTEX LOCK
	db.indices[index].ixFileMutex.RLock()
	// Filter index map
	var match bool
	db.indices[index].index.Reverse(
		func(key string, value *Index) bool {
			select {
			case <-ctx.Done():
				return false
			default:
				if match = query.MatchString(value.value); match {
					content, err := db.readFromDB(value.pos, value.len)
					if err == nil {
						entryResponse := &EntryResponse{
							uUID:  key,
							Index: value,
							Data:  content,
						}
						responses <- entryResponse
					}
				}
				return true
			}
		},
	)
	// MUTEX UNLOCK
	db.indices[index].ixFileMutex.RUnlock()
	wg.Done()
}

func (db *GoDB) readFromDB(pos int64, len int64) ([]byte, error) {
	// MUTEX LOCK
	db.dbMutex.RLock()
	// Read from disk
	_, err := db.dbFile.Seek(pos, 0)
	if err != nil {
		return nil, errors.New("err seeking in disk")
	}
	content := make([]byte, len)
	_, err = db.dbFile.Read(content)
	if err != nil {
		return nil, errors.New("err reading from disk")
	}
	// MUTEX UNLOCK
	db.dbMutex.RUnlock()
	// Return content
	return content, nil
}

func (db *GoDB) CloseDB() error {
	if db.dbFile == nil {
		return nil
	}
	err := db.dbFile.Close()
	if err != nil {
		return errors.New("db file could not be closed")
	}
	for _, value := range db.indices {
		err = value.ixFile.Close()
		if err != nil {
			return errors.New("ix file could not be closed")
		}
	}
	return nil
}

func (db *GoDB) checkIXFile(index string, level int32) error {
	filename := filepath.Join(db.workDir, "db", db.module, fmt.Sprintf("%v-%d.ix", index, level))
	if !FileExists(filename) {
		err := os.WriteFile(filename, []byte{}, 0666)
		if err != nil {
			return errors.New("index file could not be created")
		}
	}
	// Set file pointer
	ixFileTmp, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		log.Panic("err during ix file open:", err)
	}
	// Create the B-Tree holding all indices
	bTree := btree.NewMap[string, *Index](3)
	db.indices[index] = IndexMap{index: bTree, ixFile: ixFileTmp, ixFileMutex: &sync.RWMutex{}}
	// Read available stored indices and set them
	reader := csv.NewReader(ixFileTmp)
	store, err := reader.ReadAll()
	if err != nil {
		return errors.New("err reading stored indices")
	}
	var uUID string
	var pos, length int64
	storedCount := 0
	for _, value := range store {
		uUID = value[1]
		pos, err = strconv.ParseInt(value[2], 10, 64)
		if err != nil {
			return errors.New("err reading stored index (pos)")
		}
		length, err = strconv.ParseInt(value[3], 10, 64)
		if err != nil {
			return errors.New("err reading stored index (len)")
		}
		// Do we set or delete this index?
		if pos >= 0 && length >= 0 {
			if index == "uuid" {
				value[0] = ""
			}
			indexEntry := &Index{
				value: value[0],
				pos:   pos,
				len:   length,
			}
			db.indices[index].index.Set(uUID, indexEntry)
			storedCount++
		} else {
			db.indices[index].index.Delete(uUID)
			storedCount--
		}
	}
	fmt.Printf("DB %s IX %s <- LOAD %d\n", db.module, index, storedCount)
	return nil
}

func (db *GoDB) writeIXCache(index string, uUID string, indexEntry *Index) error {
	ixCache := fmt.Sprintf(
		"\"%s\",\"%s\",\"%d\",\"%d\"\n",
		indexEntry.value,
		uUID,
		indexEntry.pos,
		indexEntry.len,
	)
	ixFile := db.indices[index].ixFile
	ixFileMutex := db.indices[index].ixFileMutex
	// MUTEX LOCK
	ixFileMutex.Lock()
	// Get end of file position
	stat, err := ixFile.Stat()
	if err != nil {
		return errors.New("ix file stat failed")
	}
	offset := stat.Size()
	// Write index cache to disk
	_, err = ixFile.WriteAt([]byte(ixCache), offset)
	// MUTEX UNLOCK
	ixFileMutex.Unlock()
	if err != nil {
		return errors.New("ix file write failed")
	}
	return nil
}

// ### Utility ###

func getDBFile(module string, workDir string) string {
	return filepath.Join(workDir, "db", module, module+".db")
}

func checkDBFile(module string, workDir string) (string, error) {
	filename := getDBFile(module, workDir)
	if !FileExists(filename) {
		err := os.WriteFile(filename, []byte{}, 0666)
		if err != nil {
			return "", errors.New("db file could not be created")
		}
	}
	return filename, nil
}

func checkModuleDir(module string, workDir string) {
	err := os.Mkdir(filepath.Join(workDir, "db"), 0755)
	if err != nil && !os.IsExist(err) {
		return
	}
	err = os.Mkdir(filepath.Join(workDir, "db", module), 0755)
	if err != nil {
		return
	}
}

func (db *GoDB) writeIndices(uUID string, offset, length int64, indices map[string]string) {
	// MUTEX LOCK
	db.ixMutex.Lock()
	defer db.ixMutex.Unlock()
	// Write base index (uuid)
	indexEntry := &Index{
		value: "", // Locking field will be emptied after Insert/Update - Nice side-effect!
		pos:   offset,
		len:   length,
	}

	db.indices["uuid"].index.Set(uUID, indexEntry)
	db.ixChannel <- &IXChannelCommand{
		index:      "uuid",
		uUID:       uUID,
		indexEntry: indexEntry,
	}
	// Write custom indices
	if len(indices) > 0 {
		for key, value := range indices {
			if key == "uuid" {
				continue
			}
			if value == "" {
				// Remove empty indices
				indexEntry = &Index{
					value: "",
					pos:   -1,
					len:   -1,
				}
				db.indices[key].index.Delete(uUID)
				db.ixChannel <- &IXChannelCommand{
					index:      key,
					uUID:       uUID,
					indexEntry: indexEntry,
				}
				continue
			}
			// Store index with value
			indexEntry = &Index{
				value: value,
				pos:   offset,
				len:   length,
			}
			db.indices[key].index.Set(uUID, indexEntry)
			// Write index file
			db.ixChannel <- &IXChannelCommand{
				index:      key,
				uUID:       uUID,
				indexEntry: indexEntry,
			}
		}
	}
}
