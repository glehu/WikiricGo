package main

import (
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"log"
)

func TestBadger() {
	// Open Database
	db, err := badger.Open(badger.DefaultOptions("/tmp/badger"))
	if err != nil {
		log.Fatal(err)
	}
	// Don't forget to (later) close it :)
	defer func(db *badger.DB) {
		err := db.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(db)
	// Set an entry
	prefix := "a"
	key := "key1"
	fullKey := fmt.Sprintf("%s:%s", prefix, key)
	err = db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(fullKey), []byte("value1"))
		return err
	})
	// ... and another one!
	prefix = "a"
	key = "key2"
	fullKey = fmt.Sprintf("%s:%s", prefix, key)
	err = db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(fullKey), []byte("value2"))
		return err
	})
	// Retrieve it (attempt)
	key = "key2"
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			fmt.Printf("Value for key \"%s\" is \"%s\"\n", key, val)
			return nil
		})
		return nil
	})
	// Mass insert entries for prefix scan
	// var keyID uuid.UUID
	// for j := 1; j <= 1_000_000; j++ {
	// 	if j < 50 {
	// 		prefix = "a"
	// 	} else {
	// 		prefix = "b"
	// 	}
	// 	keyID, _ = uuid.NewV7()
	// 	key = keyID.String()
	// 	fullKey = fmt.Sprintf("%s:%s", prefix, key)
	// 	err = db.Update(func(txn *badger.Txn) error {
	// 		err := txn.Set([]byte(fullKey), []byte(fmt.Sprintf("value%d", j)))
	// 		return err
	// 	})
	// 	if math.Mod(float64(j), float64(10_000)) == 0 {
	// 		fmt.Printf("Inserted %d\n", j)
	// 	}
	// }
	// Prefix scan
	err = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := []byte("a:")
		for SeekLast(it, prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				fmt.Printf("key=%s, value=%s\n", k, v)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}
