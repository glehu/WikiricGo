package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

// ### CONST ###

const defaultIxCapacity = 2_000_000
const defaultIxValueMaxLength = 100

// ### TYPES ###

// Entry to be stored and retrieved from the database
type Entry struct {
	UUID uuid.UUID
	Data interface{}
}

type EntryResponse struct {
	Index *Index
	Data  interface{}
}

// Index points to a database entry and is being contained by a named IndexMap
type Index struct {
	value string
	pos   int64
	len   int64
}

// IndexMap is a named index map containing Index elements and a pointer to its *os.File
type IndexMap struct {
	index       map[uuid.UUID]*Index
	ixFile      *os.File
	ixFileMutex *sync.RWMutex
}

type DBSettings struct {
	ixCapacity  int64
	ixMaxLength int
}

type IXChannelCommand struct {
	index      string
	uUID       uuid.UUID
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

// DB Interface
type DB interface {
	// Storage Methods

	Insert(data interface{}, indices map[string]string) error

	Select(indices map[string]string) (<-chan interface{}, error)

	// Utility Methods

	// CloseDB closes the database file
	CloseDB() error

	// Internal Methods

	CheckIXFile(index string, level int32) error
	GetIXCacheLength() int
	WriteIXCache(index string, uUID uuid.UUID, indexEntry *Index) error
}

// OpenDB creates a named database
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
	// Check index files
	for _, indexName := range indices {
		err := goDB.CheckIXFile(indexName, 0)
		if err != nil {
			log.Panic("err during db ix file check")
		}
	}
	go startIXFileWorker(goDB, ixChannelTmp)
	return goDB
}

func startIXFileWorker(goDB *GoDB, jobs <-chan *IXChannelCommand) {
	for job := range jobs {
		err := goDB.WriteIXCache(job.index, job.uUID, job.indexEntry)
		if err != nil {
			log.Panic("ix cache write fail:", err)
		}
	}
}

// ### DB Functions ###

// Insert adds an object to the database
func (goDB *GoDB) Insert(obj interface{}, indices map[string]string) error {
	// Generate UUID
	uUID := uuid.New()
	entry := Entry{
		UUID: uUID,
		Data: obj,
	}
	data, _ := json.Marshal(entry)
	// MUTEX LOCK
	goDB.dbMutex.Lock()
	// Find end of file position
	stat, err := goDB.dbFile.Stat()
	if err != nil {
		return errors.New("db file stat failed")
	}
	//offset, err := goDB.dbFile.Seek(stat.Size(), 0)
	offset := stat.Size()
	// Write bytes
	_, err = goDB.dbFile.WriteAt(data, offset)
	// MUTEX UNLOCK
	goDB.dbMutex.Unlock()
	if err != nil {
		return errors.New("db write failed")
	}
	// Write indices
	if len(indices) > 0 {
		// MUTEX LOCK
		goDB.ixMutex.Lock()
		for key, value := range indices {
			indexEntry := &Index{
				value: value,
				pos:   offset,
				len:   int64(len(data)),
			}
			goDB.indices[key].index[uUID] = indexEntry
			key := key
			goDB.ixChannel <- &IXChannelCommand{
				index:      key,
				uUID:       uUID,
				indexEntry: indexEntry,
			}
		}
		// MUTEX UNLOCK
		goDB.ixMutex.Unlock()
	}
	return nil
}

func (goDB *GoDB) Select(indices map[string]string) (chan []interface{}, error) {
	// Test indices
	indicesClean := make(map[string]string)
	for key, value := range indices {
		if _, present := goDB.indices[key]; present {
			indicesClean[key] = value
		}
	}
	if len(indicesClean) < 1 {
		return nil, errors.New("no valid index queries provided")
	}
	wg := sync.WaitGroup{}
	responsesInternal := make(chan *EntryResponse)
	responsesExternal := make(chan []interface{})
	done := make(chan bool)
	for key, value := range indicesClean {
		wg.Add(1)
		go goDB.singleIndexQuery(key, value, responsesInternal, &wg)
	}

	go func() {
		wg.Wait()
		done <- true
	}()
	go func() {
		sortedEntries := make([]*EntryResponse, 0)
		for true {
			select {
			case <-done:
				close(responsesInternal)
				sort.SliceStable(sortedEntries, func(i, j int) bool {
					return sortedEntries[i].Index.pos > sortedEntries[j].Index.pos
				})
				sortedResponse := make([]interface{}, len(sortedEntries))
				for index, value := range sortedEntries {
					sortedResponse[index] = value.Data
				}
				responsesExternal <- sortedResponse
				close(responsesExternal)
				return
			case entry := <-responsesInternal:
				// responsesExternal <- entry
				sortedEntries = append(sortedEntries, entry)
			}
		}
	}()
	return responsesExternal, nil
}

func (goDB *GoDB) singleIndexQuery(index string, query string, responses chan *EntryResponse, wg *sync.WaitGroup) {
	// MUTEX LOCK
	goDB.indices[index].ixFileMutex.RLock()
	// Filter index map
	var match bool
	for _, value := range goDB.indices[index].index {
		if match, _ = regexp.MatchString(query, value.value); match {
			content, err := goDB.ReadFromDB(value.pos, value.len)
			if err == nil {
				entry := &Entry{}
				err := json.Unmarshal(content, entry)
				if err == nil {
					entryResponse := &EntryResponse{
						Index: value,
						Data:  entry,
					}
					responses <- entryResponse
				}
			}
		}
	}
	// MUTEX UNLOCK
	goDB.indices[index].ixFileMutex.RUnlock()
	wg.Done()
}

func (goDB *GoDB) ReadFromDB(pos int64, len int64) ([]byte, error) {
	// MUTEX LOCK
	goDB.dbMutex.RLock()
	// Read from disk
	_, err := goDB.dbFile.Seek(pos, 0)
	if err != nil {
		return nil, errors.New("err seeking in disk")
	}
	content := make([]byte, len)
	_, err = goDB.dbFile.Read(content)
	if err != nil {
		return nil, errors.New("err reading from disk")
	}
	// MUTEX UNLOCK
	goDB.dbMutex.RUnlock()
	// Return content
	return content, nil
}

func (goDB *GoDB) CloseDB() error {
	if goDB.dbFile == nil {
		return nil
	}
	err := goDB.dbFile.Close()
	if err != nil {
		return errors.New("db file could not be closed")
	}
	for _, value := range goDB.indices {
		err = value.ixFile.Close()
		if err != nil {
			return errors.New("ix file could not be closed")
		}
	}
	return nil
}

func (goDB *GoDB) CheckIXFile(index string, level int32) error {
	filename := filepath.Join(goDB.workDir, "db", goDB.module, fmt.Sprintf("%v-%d.ix", index, level))
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
	goDB.indices[index] = IndexMap{index: map[uuid.UUID]*Index{}, ixFile: ixFileTmp, ixFileMutex: &sync.RWMutex{}}
	return nil
}

func (goDB *GoDB) GetIXCacheLength() int {
	// UUID
	cacheLength := 16
	// Index Value
	cacheLength += goDB.DBSettings.ixMaxLength
	// DB Pos & Size
	cacheLength += 19 + 19
	// Delimiter
	cacheLength += 1
	return cacheLength
}

func (goDB *GoDB) WriteIXCache(index string, uUID uuid.UUID, indexEntry *Index) error {
	ixCache := fmt.Sprintf(
		"%-16s%-100s%-19s%-19s;",
		uUID.String(),
		indexEntry.value,
		strconv.FormatInt(indexEntry.pos, 10),
		strconv.FormatInt(indexEntry.len, 10),
	)
	ixFile := goDB.indices[index].ixFile
	ixFileMutex := goDB.indices[index].ixFileMutex
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
