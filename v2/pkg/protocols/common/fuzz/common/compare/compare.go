package compare

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/martinohmann/go-difflib/difflib"
)

const (
	UpperRatioBound = 0.98
	LowerRatioBound = 0.02
)

// CompareResponses compares two responses and returns true if they are equal
//
// The comparison is done by normalizing the responses and comparing them
// using the sequencematcher from difflib class.
func CompareResponses(response1, response2 string) bool {
	firstTokens := normalizeResponseBody(response1)
	secondTokens := normalizeResponseBody(response2)

	if len(firstTokens) > len(secondTokens) {
		firstTokens, secondTokens = secondTokens, firstTokens
	}
	matcher := difflib.NewMatcher(firstTokens, secondTokens)
	// TODO: Handle extremely dynamic pages differently.
	ratio := matcher.QuickRatio()
	fmt.Printf("Ratio: %f\n", ratio)
	if ratio > UpperRatioBound {
		return true
	}
	if ratio < LowerRatioBound {
		return false
	}
	return false
}

var (
	// splitMostPreciseDelim is the most precise delimiter for splitting
	// the response body into tokens without whitespace or colon.
	splitMostPreciseDelim = regexp.MustCompile(`[,{}\"\r\t\n]+`)
)

// normalizeResponseBody normalizes the response body from
// a page converting it into a list of individual tokens for the page.
//
// The process begins by splitting of the text content using delimiters
// then further normalizing it based on the response discovered.
func normalizeResponseBody(text string) []string {
	text = splitMostPreciseDelim.ReplaceAllString(text, "\n")
	return strings.Split(text, "\n")
}
