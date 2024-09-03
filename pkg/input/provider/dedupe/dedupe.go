// Package dedupe implements a duplicate URL deduplication mechanism
// for Nuclei DAST or Fuzzing inputs.
//
// It is used to remove similar or non-relevant inputs from fuzzing
// or DAST scans to reduce the number of requests made.
package dedupe

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	mapsutil "github.com/projectdiscovery/utils/maps"
)

// FuzzingDeduper is a deduper for fuzzing inputs
//
// The normalization works as follows:
//
//   - The path is normalized to remove any trailing slashes
//   - The query is normalized by templating the query parameters with their names
//     TODO: Doesn't handle different values, everything is stripped. Maybe make it more flexible?
//   - Numeric IDs in the path are replaced with {numeric_id}
//
// This allows us to deduplicate URLs with different query parameters
// or orders but the same structure or key names.
type FuzzingDeduper struct {
	items *mapsutil.SyncLockMap[string, struct{}]
}

// NewFuzzingDeduper creates a new fuzzing deduper
func NewFuzzingDeduper() *FuzzingDeduper {
	return &FuzzingDeduper{
		items: mapsutil.NewSyncLockMap[string, struct{}](),
	}
}

// Add adds a new URL to the deduper
func (d *FuzzingDeduper) Add(URL string) bool {
	generatedPattern, err := generatePattern(URL)
	if err != nil {
		return false
	}

	_, found := d.items.Get(generatedPattern)
	if found {
		return false
	}
	d.items.Set(generatedPattern, struct{}{})
	return true
}

func generatePattern(urlStr string) (string, error) {
	parsedURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return "", err
	}

	path := normalizePath(parsedURL.Path)
	query := extractQuery(parsedURL.Query())

	var builder strings.Builder
	builder.Grow(len(urlStr))
	builder.WriteString(parsedURL.Scheme)
	builder.WriteString("://")
	builder.WriteString(parsedURL.Host)
	builder.WriteString(path)
	if query != "" {
		builder.WriteString("?")
		builder.WriteString(query)
	}
	pattern := builder.String()
	return pattern, nil
}

var (
	numericIDPathRegex = regexp.MustCompile(`/(\d+)(?:/|$)`)
)

func normalizePath(path string) string {
	subMatches := numericIDPathRegex.FindAllStringSubmatch(path, -1)
	for _, match := range subMatches {
		path = strings.ReplaceAll(path, match[0], "/{numeric_id}")
	}
	return path
}

func extractQuery(query url.Values) string {
	normalizedParams := make([]string, 0, len(query))

	for k, v := range query {
		if len(v) == 0 {
			normalizedParams = append(normalizedParams, k)
		} else {
			normalizedParams = append(normalizedParams, fmt.Sprintf("%s={%s}", k, k))
		}
	}
	slices.Sort(normalizedParams)
	return strings.Join(normalizedParams, "&")
}
