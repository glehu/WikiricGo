package main

type Wisdom struct {
	Name          string   `json:"t"`
	Description   string   `json:"desc"`
	Keywords      string   `json:"keys"`
	Type          string   `json:"type"`
	TimeCreated   string   `json:"ts"`
	KnowledgeUUID string   `json:"pid"`
	Categories    []string `json:"cats"`
	ReferenceUUID string   `json:"ref"` // References another Wisdom e.g. Comment referencing Answer
	AnalyticsUUID string   `json:"ana"` // Views, likes etc. will be stored in a separate database
}
