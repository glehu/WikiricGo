package main

import "unicode"

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
