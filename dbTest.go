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
	db := OpenDB("debug", []string{"count"})
	defer func() {
		err := db.CloseDB()
		if err != nil {
			log.Fatal(err)
		}
	}()
	// Store Data
	testStore(db)
	// Retrieve Data
	testSelect(db)
}

func testStore(db *GoDB) {
	fmt.Println(">>> DEBUG DB STORE START")
	time.Sleep(time.Second)
	start := time.Now()
	// Store data in database
	for i := 1; i <= 10_000; i++ {
		count := fmt.Sprintf("%d", i)
		// Serialize data
		data, err := json.Marshal(&SampleEntry{
			Field:       "Sample Contact",
			Description: "Mr Sample Name " + count,
			Age:         i,
			Website:     true,
			Skills:      map[string]string{"german": "native", "english": "veri nais"},
		})
		if err != nil {
			log.Fatal(":: DEBUG ERROR serializing", err)
		}
		// Insert into db
		err = db.Insert(data, map[string]string{
			"count": count,
		})
		if err != nil {
			log.Fatal(":: DEBUG ERROR inserting", err)
		}
		if math.Mod(float64(i), float64(10_000)) == 0 {
			fmt.Printf("> Inserted %d\n", i)
		}
	}
	fmt.Printf(">>> DEBUG DB STORE END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}

func testSelect(db *GoDB) {
	fmt.Println(">>> DEBUG DB SELECT START")
	time.Sleep(time.Second)
	start := time.Now()
	// Retrieve data from database
	resp, err := db.Select(map[string]string{
		"count": "^888$",
	})
	if err != nil {
		log.Fatal(err)
	}
	// Listen for the response
	arr := <-resp
	timeRan := time.Since(start).Seconds()
	fmt.Printf(">> Results: %d\n", len(arr))
	for index, entry := range arr {
		// Deserialize
		adr := &SampleEntry{}
		err := json.Unmarshal(entry.Data, adr)
		if err != nil {
			continue
		}
		fmt.Printf("%d > %s %s\n", index, entry.Index.uuid7, adr.Description)
	}
	fmt.Printf("\n>>> DEBUG DB SELECT END after %f s\n", timeRan)
	time.Sleep(time.Second)
}
