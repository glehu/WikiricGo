package main

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

type SampleEntry struct {
	Field       string
	Description string
	Age         int
	Website     bool
}

func testDB() {
	db := OpenDB("debug", []string{"count"})
	defer func() {
		err := db.CloseDB()
		if err != nil {
			return
		}
	}()
	// Store Data
	testStore(db)
	// Retrieve Data
	testSelect(db)
}

func testStore(db *GoDB) {
	time.Sleep(time.Second)
	fmt.Println(">>> DEBUG DB STORE START")
	start := time.Now()
	// Store data in database
	for i := 1; i <= 100; i++ {
		count := fmt.Sprintf("%d", i)
		sample := &SampleEntry{
			Field:       "Sample Contact",
			Description: "Mr Sample Name " + count,
			Age:         i,
			Website:     true,
		}
		err := db.Insert(sample, map[string]string{
			"count": count,
		})
		if err != nil {
			return
		}
		if math.Mod(float64(i), float64(100)) == 0 {
			fmt.Printf("> %d\n", i)
		}
	}
	fmt.Printf(">>> DEBUG DB STORE END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}

func testSelect(db *GoDB) {
	time.Sleep(time.Second)
	fmt.Println(">>> DEBUG DB SELECT START")
	start := time.Now()
	// Retrieve data from database
	resp, err := db.Select(map[string]string{
		"count": "^(69|420|666|777|999)$",
	})
	if err != nil {
		return
	}
	arr := <-resp
	fmt.Printf(">> Results: %d\n", len(arr))
	for _, entry := range arr {
		adr := entryToObj(entry)
		fmt.Println(">", adr.Description)
	}
	fmt.Printf(">>> DEBUG DB SELECT END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}

func entryToObj(entry interface{}) SampleEntry {
	ent := entry.(*Entry).Data
	adt, _ := json.Marshal(ent)
	adr := SampleEntry{}
	_ = json.Unmarshal(adt, &adr)
	return adr
}
