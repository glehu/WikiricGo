package main

import "time"

func TimeNowIsoString() string {
	return time.Now().Format(time.RFC3339)
}
