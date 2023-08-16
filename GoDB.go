package main

import (
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
)

// ### CONST ###

const defaultIxCapacity = 2_000_000
const defaultIxValueMaxLength = 100

// ### TYPES ###

type EntryResponse struct {
	Index *Index
	Data  []byte
}

// Index points to a database entry and is being contained by a named IndexMap
type Index struct {
	value string
	uuid7 uuid.UUID
	pos   int64
	len   int64
}

// IndexMap is a named index map containing Index elements and a pointer to its *os.File
type IndexMap struct {
	index       *btree.BTreeG[*Index]
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

	Insert(data []byte, indices map[string]string) error

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

// OpenDB creates a named database
func OpenDB(module string, indices []string) *GoDB {
	// Set working directory
	workDirTmp, _ := os.Getwd()
	checkModuleDir(module, workDirTmp)
	// Create DB file if missing
	databaseFilename, err := checkDBFile(module, workDirTmp)
	if err != nil {
		log.Fatal("err during db file check:", err)
	}
	// Set file pointer
	dbFileTmp, err := os.OpenFile(databaseFilename, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal("err during db file open:", err)
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
		err := goDB.checkIXFile(indexName, 0)
		if err != nil {
			log.Fatal("err during db ix file check", err)
		}
	}
	go startIXFileWorker(goDB, ixChannelTmp)
	return goDB
}

func startIXFileWorker(goDB *GoDB, jobs <-chan *IXChannelCommand) {
	for job := range jobs {
		err := goDB.writeIXCache(job.index, job.uUID, job.indexEntry)
		if err != nil {
			log.Fatal("ix cache write fail:", err)
		}
	}
}

// ### DB Functions ###

// Insert adds an object to the database
func (goDB *GoDB) Insert(data []byte, indices map[string]string) error {
	// Generate UUID
	uUID, err := uuid.NewV7()
	if err != nil {
		log.Fatal("err generating uuid", err)
	}
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
				uuid7: uUID,
				pos:   offset,
				len:   int64(len(data)),
			}

			goDB.indices[key].index.Set(indexEntry)
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

func (goDB *GoDB) Select(indices map[string]string) (chan []*EntryResponse, error) {
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
	responsesExternal := make(chan []*EntryResponse)
	done := make(chan bool)
	for key, value := range indicesClean {
		wg.Add(1)
		query, err := regexp.Compile(value)
		if err == nil {
			go goDB.singleIndexQuery(key, query, responsesInternal, &wg)
		}
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
				// Sort by uuid V7 to ensure order of returned values
				sort.SliceStable(sortedEntries, func(i, j int) bool {
					return sortedEntries[i].Index.uuid7.String() > sortedEntries[j].Index.uuid7.String()
				})
				// Send back to receiver
				responsesExternal <- sortedEntries
				close(responsesExternal)
				return
			case entry := <-responsesInternal:
				// Collect all found values
				sortedEntries = append(sortedEntries, entry)
			}
		}
	}()
	return responsesExternal, nil
}

func (goDB *GoDB) singleIndexQuery(index string, query *regexp.Regexp, responses chan *EntryResponse, wg *sync.WaitGroup) {
	// MUTEX LOCK
	goDB.indices[index].ixFileMutex.RLock()
	// Filter index map
	var match bool
	goDB.indices[index].index.Reverse(func(value *Index) bool {
		if match = query.MatchString(value.value); match {
			content, err := goDB.readFromDB(value.pos, value.len)
			if err == nil {
				entryResponse := &EntryResponse{
					Index: value,
					Data:  content,
				}
				responses <- entryResponse
			}
		}
		return true
	})
	// MUTEX UNLOCK
	goDB.indices[index].ixFileMutex.RUnlock()
	wg.Done()
}

func (goDB *GoDB) readFromDB(pos int64, len int64) ([]byte, error) {
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

func (goDB *GoDB) checkIXFile(index string, level int32) error {
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
	// Create the B-Tree holding all indices
	bTree := btree.NewBTreeG[*Index](IndexComparator)
	goDB.indices[index] = IndexMap{index: bTree, ixFile: ixFileTmp, ixFileMutex: &sync.RWMutex{}}
	// Read available stored indices and set them
	reader := csv.NewReader(ixFileTmp)
	store, err := reader.ReadAll()
	if err != nil {
		return errors.New("err reading stored indices")
	}
	var uUID uuid.UUID
	var pos, length int64
	storedCount := 0
	for _, value := range store {
		uUID, err = uuid.FromString(value[1])
		if err != nil {
			return errors.New("err reading stored index (uuid)")
		}
		pos, err = strconv.ParseInt(value[2], 10, 64)
		if err != nil {
			return errors.New("err reading stored index (pos)")
		}
		length, err = strconv.ParseInt(value[3], 10, 64)
		if err != nil {
			return errors.New("err reading stored index (len)")
		}
		indexEntry := &Index{
			value: value[0],
			uuid7: uUID,
			pos:   pos,
			len:   length,
		}
		goDB.indices[index].index.Set(indexEntry)
		storedCount++
	}
	fmt.Printf("DB %s IX %s <- LOAD %d\n", goDB.module, index, storedCount)
	return nil
}

func (goDB *GoDB) writeIXCache(index string, uUID uuid.UUID, indexEntry *Index) error {
	ixCache := fmt.Sprintf(
		"\"%s\",\"%s\",\"%d\",\"%d\"\n",
		indexEntry.value,
		uUID.String(),
		indexEntry.pos,
		indexEntry.len,
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

func IndexComparatorBackup(a, b *Index) bool {
	return a.uuid7.String() < b.uuid7.String()
}

func IndexComparator(a, b *Index) bool {
	if a.value < b.value {
		return true
	} else if a.value > b.value {
		return false
	}
	return IndexComparatorBackup(a, b)
}

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
