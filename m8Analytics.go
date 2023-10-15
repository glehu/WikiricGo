package main

type Analytics struct {
	Views     int64      `json:"views"`
	Reactions []Reaction `json:"reacts"` // Map of reactions e.g. upvote (+) with usernames
	Downloads int64      `json:"downl"`
	Bookmarks int64      `json:"bookm"`
}

type Reaction struct {
	Type      string   `json:"t"`
	Usernames []string `json:"src"`
}

func OpenAnalyticsDatabase() *GoDB {
	db := OpenDB("analytics")
	return db
}
