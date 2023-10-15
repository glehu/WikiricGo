package main

import "time"

func TimeNowIsoString() string {
	return TimeToIsoString(time.Now().UTC())
}

// TimeToIsoString returns the ISO date time string for the provided time.Time
//
// Example date time:
//
// 2006-01-02T15:04:05Z07:00
func TimeToIsoString(t time.Time) string {
	return t.Format(time.RFC3339)
}

// IsoStringToTime returns the time.Time for the provided ISO date time string
//
// Example date time:
//
// 2006-01-02T15:04:05Z07:00
func IsoStringToTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
