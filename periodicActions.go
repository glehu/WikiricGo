package main

import (
	"fmt"
	"time"
)

func StartPeriodicLoop(done chan bool) {
	ticker := time.NewTicker(time.Minute * 30)
	go tickLoop(ticker, done)
	fmt.Println(":: Periodic Loop Started")
}

func tickLoop(ticker *time.Ticker, done chan bool) {
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			go triggerActions()
		}
	}
}

func triggerActions() {
	// Actions:
}
