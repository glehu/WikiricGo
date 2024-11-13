package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
)

func EllipticalTruncate(text string, maxLen int) string {
	if maxLen >= len(text) {
		return text
	}
	lastSpaceIx := maxLen
	length := 0
	for i, r := range text {
		if unicode.IsSpace(r) {
			lastSpaceIx = i
		}
		length++
		if length > maxLen {
			return text[:lastSpaceIx] + "..."
		}
	}
	return text
}

func CheckPrefix(text, prefix string) bool {
	// Since we assume correct usage we cannot return true if there is no real match
	if text == "" || prefix == "" || len(text) < len(prefix) {
		return false
	}
	return text[0:len(prefix)] == prefix
}

// JsonStringify turns a struct to a white-space trimmed JSON string
func JsonStringify(v interface{}) (string, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf.Bytes())), nil
}
