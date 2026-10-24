// Package dedupe provides request-level deduplication for HTTP inputs used by
// fuzzing / DAST (burp, openapi, proxify dumps, live dast-server, etc.).
package dedupe

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Headers that commonly change between equivalent requests and should not
// affect the fingerprint used for deduplication.
var dynamicHeaders = map[string]bool{
	"date":                true,
	"if-modified-since":   true,
	"if-unmodified-since": true,
	"cache-control":       true,
	"if-none-match":       true,
	"if-match":            true,
	"authorization":       true,
	"cookie":              true,
	"x-csrf-token":        true,
	"content-length":      true,
	"content-md5":         true,
	"host":                true,
	"x-request-id":        true,
	"x-correlation-id":    true,
	"user-agent":          true,
	"referer":             true,
}

// RequestDeduplicator tracks seen HTTP requests by a stable fingerprint.
type RequestDeduplicator struct {
	hashes map[string]struct{}
	lock   sync.RWMutex
}

// NewRequestDeduplicator creates an empty request deduplicator.
func NewRequestDeduplicator() *RequestDeduplicator {
	return &RequestDeduplicator{
		hashes: make(map[string]struct{}),
	}
}

// IsDuplicate returns true if an equivalent request was already seen.
// The first occurrence of a fingerprint is recorded and returns false.
func (r *RequestDeduplicator) IsDuplicate(req *types.RequestResponse) bool {
	if req == nil {
		return false
	}
	hash, err := HashRequest(req)
	if err != nil || hash == "" {
		return false
	}

	r.lock.RLock()
	_, ok := r.hashes[hash]
	r.lock.RUnlock()
	if ok {
		return true
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.hashes[hash]; ok {
		return true
	}
	r.hashes[hash] = struct{}{}
	return false
}

// Len returns the number of unique fingerprints recorded.
func (r *RequestDeduplicator) Len() int {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return len(r.hashes)
}

// HashRequest builds a stable fingerprint for a request:
// method + normalized URL + non-dynamic headers + body.
func HashRequest(req *types.RequestResponse) (string, error) {
	if req == nil || req.URL.URL == nil {
		return "", nil
	}

	normalizedURL, err := NormalizeURL(req.URL.URL)
	if err != nil {
		return "", err
	}

	var hashContent strings.Builder
	method := "GET"
	var body string
	var headers mapsutil.OrderedMap[string, string]
	if req.Request != nil {
		if req.Request.Method != "" {
			method = strings.ToUpper(req.Request.Method)
		}
		body = req.Request.Body
		headers = req.Request.Headers
	}
	hashContent.WriteString(method)
	hashContent.WriteString(normalizedURL)

	for _, header := range sortedNonDynamicHeaders(headers) {
		hashContent.WriteString(header.Key)
		hashContent.WriteString(header.Value)
	}

	if len(body) > 0 {
		hashContent.WriteString(body)
	}

	hash := sha256.Sum256([]byte(hashContent.String()))
	return hex.EncodeToString(hash[:]), nil
}

// NormalizeURL returns a stable string form of u without mutating the original.
func NormalizeURL(u *url.URL) (string, error) {
	if u == nil {
		return "", nil
	}
	cloned := *u
	query := cloned.Query()
	sortedQuery := make(url.Values, len(query))
	for k, v := range query {
		sorted := append([]string(nil), v...)
		sort.Strings(sorted)
		sortedQuery[k] = sorted
	}
	cloned.RawQuery = sortedQuery.Encode()
	if cloned.Path == "" {
		cloned.Path = "/"
	}
	return cloned.String(), nil
}

type header struct {
	Key   string
	Value string
}

func sortedNonDynamicHeaders(headers mapsutil.OrderedMap[string, string]) []header {
	var result []header
	headers.Iterate(func(k, v string) bool {
		if !dynamicHeaders[strings.ToLower(k)] {
			result = append(result, header{Key: strings.ToLower(k), Value: v})
		}
		return true
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].Key < result[j].Key
	})
	return result
}
