package main

import (
	"fmt"
	uuid7 "github.com/gofrs/uuid"
	btree2 "github.com/tidwall/btree"
	"math"
	"time"
)

func TestBTreeG() {
	fmt.Println(">>> DEBUG B-TREE STORE START")
	time.Sleep(time.Second)
	start := time.Now()
	// Create B-Tree
	btree := btree2.NewBTreeG[*Index](IndexComparator)
	// Insert entries
	for i := 1; i <= 1_000_000; i++ {
		uUID, _ := uuid7.NewV7()
		val := uUID.String()
		if i > 500_000 && i < 500_100 {
			val = "FIND_ME"
		}
		item := &Index{
			value: val,
			uuid7: uUID,
			pos:   0,
			len:   0,
		}
		btree.Set(item)
		if math.Mod(float64(i), float64(1_000)) == 0 {
			fmt.Printf("> %d\n", i)
		}
	}
	fmt.Printf(">>> DEBUG B-TREE STORE END after %f s\n", time.Since(start).Seconds())
	fmt.Println(">>> DEBUG B-TREE Reverse START")
	time.Sleep(time.Second)
	start = time.Now()
	// Select from B-Tree
	btree.Reverse(func(item *Index) bool {
		if item.value == "FIND_ME" {
			fmt.Println(">", item)
		}
		return true
	})
	fmt.Printf(">>> DEBUG B-TREE Reverse END after %f s\n", time.Since(start).Seconds())
	time.Sleep(time.Second)
}
