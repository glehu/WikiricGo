package main

type Analytics struct {
	Views     int64               `json:"views"`
	Reactions map[string][]string `json:"reacts"` // Map of reactions e.g. upvote + usernames
	Downloads int64               `json:"downl"`
	Bookmarks int64               `json:"bookm"`
}

func OpenAnalyticsDatabase() *GoDB {
	db := OpenDB("analytics", []string{})
	return db
}
