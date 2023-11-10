package main

import (
	"fmt"
	"regexp"
	"strings"
)

// GetRegexQuery converts a string of words into a regex pattern
// Example:
//
//	Query "ice cream cones" would turn into...
//		((ice)(\s?cream)?(\s?cones)?|(cream)(\s?cones)?|(cones))
//	Thus creating a list of words as following...
//		ice cream cones icecream creamcones icecreamcones
func GetRegexQuery(query string) (map[string]*QueryWord, *regexp.Regexp) {
	// Remove leading and trailing spaces
	clean := strings.TrimSpace(query)
	if clean == "" {
		return map[string]*QueryWord{}, nil
	}
	// Replace duplicate spaces with singular spaces
	spaces := regexp.MustCompile("\\s+")
	clean = spaces.ReplaceAllString(clean, " ")
	// Split query into words
	words := strings.Split(clean, " ")
	wordCount := len(words)
	builder := &strings.Builder{}
	// Case-insensitive
	builder.WriteString("(?i)")
	// Attach all words
	wordMap := map[string]*QueryWord{}
	var queryWord *QueryWord
	for i, word := range words {
		wordMap[word] = &QueryWord{
			B:      false,
			Points: 1,
		}
		if i > 0 {
			// Add alternation if we're on the second iteration and onwards
			builder.WriteString("|")
		}
		// Single word
		builder.WriteString("(")
		builder.WriteString(word)
		builder.WriteString(")")
		// Neighboring words
		if i < wordCount-1 && wordCount > 1 {
			queryWord = &QueryWord{
				B:      false,
				Points: 2, // 1 + Group Bonus = 2
			}
			// Attach neighbor to ensure context is being captured better
			wordMap[fmt.Sprintf("%s%s", words[i], words[i+1])] = queryWord
			wordMap[fmt.Sprintf("%s-%s", words[i], words[i+1])] = queryWord
			wordMap[fmt.Sprintf("%s-%s", words[i], words[i+1])] = queryWord
			builder.WriteString("((\\s|-)?")
			builder.WriteString(words[i+1])
			builder.WriteString(")?")
		}
	}
	return wordMap, regexp.MustCompile(builder.String())
}
