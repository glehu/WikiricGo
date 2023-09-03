package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"time"
)

type SampleEntry struct {
	Field       string
	Description string
	Age         int
	Website     bool
	Skills      map[string]string
}

func TestDB() {
	db := OpenDB("debug")
	defer func() {
		err := db.CloseDB()
		if err != nil {
			log.Panic(err)
		}
	}()
	// Store Data
	testStore(db)
	// Retrieve Data
	uUID := testSelect(db)
	// Update Data
	testUpdate(db, uUID)
	// Retrieve Data
	testSelect(db)
	// Delete Data
	testDelete(db, uUID)
	// Retrieve Data
	testSelect(db)
}

func testStore(db *GoDB) {
	fmt.Println(">>> DEBUG DB STORE START")
	time.Sleep(time.Second)
	start := time.Now()
	// Store data in database
	for i := 1; i <= 1_000_000; i++ {
		count := fmt.Sprintf("%d", i)
		// Serialize data
		data, err := json.Marshal(&SampleEntry{
			Field:       "Sample Contact",
			Description: "Mr Sample Name",
			Age:         i,
			Website:     true,
			Skills:      map[string]string{"german": "native", "english": "veri nais"},
		})
		if err != nil {
			log.Panic(":: DEBUG ERROR serializing", err)
		}
		// Insert into db
		_, err = db.Insert(data, map[string]string{
			"count": count,
		})
		if err != nil {
			log.Panic(":: DEBUG ERROR inserting", err)
		}
		if math.Mod(float64(i), float64(10_000)) == 0 {
			fmt.Printf("Inserted %d\n", i)
		}
	}
	fmt.Printf(">>> DEBUG DB STORE END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}

func testSelect(db *GoDB) string {
	debugUUID := ""
	fmt.Println(">>> DEBUG DB SELECT START")
	time.Sleep(time.Second)
	start := time.Now()
	// Retrieve data from database
	resp, err := db.Select(map[string]string{
		"count": "1",
	}, &SelectOptions{
		MaxResults: 1,
		Page:       0,
		Skip:       0,
	})
	if err != nil {
		log.Panic(err)
	}
	// Listen for the response
	arr := <-resp
	timeRan := time.Since(start).Seconds()
	fmt.Printf("Results: %d\n", len(arr))
	for index, entry := range arr {
		// Deserialize
		adr := &SampleEntry{}
		err := json.Unmarshal(entry.Data, adr)
		if err != nil {
			continue
		}
		fmt.Printf("%d > %s %s\n", index, entry.uUID, adr.Description)
		debugUUID = entry.uUID
	}
	fmt.Printf(">>> DEBUG DB SELECT END after %f s\n", timeRan)
	time.Sleep(time.Second)
	return debugUUID
}

func testDelete(db *GoDB, uUID string) {
	fmt.Println(">>> DEBUG DB DELETE START")
	time.Sleep(time.Second)
	start := time.Now()
	// Delete entry from database
	err := db.Delete(uUID)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf(">>> DEBUG DB DELETE END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}

func testUpdate(db *GoDB, uUID string) {
	fmt.Println(">>> DEBUG DB UPDATE START")
	time.Sleep(time.Second)
	start := time.Now()
	// Update entry in database
	_, txn := db.Get(uUID)
	defer txn.Discard()
	// Serialize data
	data, err := json.Marshal(&SampleEntry{
		Field:       "Sample Contact",
		Description: "Mr Sample Name 1337 UPDATED!!!",
		Age:         1337,
		Website:     true,
		Skills:      map[string]string{"german": "native", "english": "veri nais"},
	})
	if err != nil {
		log.Panic(":: DEBUG ERROR serializing", err)
	}
	// Insert into db
	err = db.Update(txn, uUID, data, map[string]string{
		"count": "1337",
	})
	if err != nil {
		log.Panic(":: DEBUG ERROR updating", err)
	}
	fmt.Printf(">>> DEBUG DB UPDATE END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}
