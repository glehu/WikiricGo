package main

type Category struct {
	Name     string `json:"t"`
	ColorHex string `json:"hex"`
}

type Knowledge struct {
	Name          string     `json:"t"`
	Description   string     `json:"desc"`
	TimeCreated   string     `json:"ts"`
	ChatGroupUUID string     `json:"pid"`
	Categories    []Category `json:"cats"`
}
