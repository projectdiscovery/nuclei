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
// affect the fingerprint used for deduplication. Cookie and Authorization are
// not here: requests that differ only in credentials are distinct (e.g. for
// authorization or IDOR testing), so their normalized values are part of the
// fingerprint.
var dynamicHeaders = map[string]bool{
	"date":                true,
	"if-modified-since":   true,
	"if-unmodified-since": true,
	"cache-control":       true,
	"if-none-match":       true,
	"if-match":            true,
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
	// NUL separators keep field boundaries unambiguous, so "ab"+"c" and
	// "a"+"bc" do not hash the same.
	hashContent.WriteString(method)
	hashContent.WriteByte(0)
	hashContent.WriteString(normalizedURL)

	for _, header := range sortedNonDynamicHeaders(headers) {
		hashContent.WriteByte(0)
		hashContent.WriteString(header.Key)
		hashContent.WriteByte(0)
		hashContent.WriteString(header.Value)
	}

	if len(body) > 0 {
		hashContent.WriteByte(0)
		hashContent.WriteString(body)
	}

	hash := sha256.Sum256([]byte(hashContent.String()))
	return hex.EncodeToString(hash[:]), nil
}

// NormalizeURL returns a stable string form of u without mutating the original.
// Scheme and host are lowercased, query keys are sorted and the fragment is
// dropped since it is never sent to the server. The values of a repeated key
// keep their order, because servers can use the first or the last value. A
// query that does not parse is kept as sent, so no malformed pair is dropped.
func NormalizeURL(u *url.URL) (string, error) {
	if u == nil {
		return "", nil
	}
	cloned := *u
	cloned.Scheme = strings.ToLower(cloned.Scheme)
	cloned.Host = strings.ToLower(cloned.Host)
	cloned.Fragment = ""
	cloned.RawFragment = ""
	if query, err := url.ParseQuery(cloned.RawQuery); err == nil {
		// Encode sorts the keys and keeps the order of the values of each key.
		cloned.RawQuery = query.Encode()
	}
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
		key := strings.ToLower(k)
		if dynamicHeaders[key] {
			return true
		}
		switch key {
		case "cookie":
			v = normalizeCookie(v)
		case "authorization":
			v = normalizeAuthorization(v)
		}
		result = append(result, header{Key: key, Value: v})
		return true
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].Key < result[j].Key
	})
	return result
}

// normalizeCookie sorts the cookie pairs so that only their order does not make
// two requests different. Empty pairs are dropped; names and values are kept
// as sent, since both are case sensitive. When a name occurs more than once,
// the pairs keep their order, because servers can use the first or the last
// value.
func normalizeCookie(value string) string {
	parts := strings.Split(value, ";")
	pairs := parts[:0]
	names := make(map[string]struct{}, len(parts))
	unique := true
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			pairs = append(pairs, part)
			name, _, _ := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if _, seen := names[name]; seen {
				unique = false
			}
			names[name] = struct{}{}
		}
	}
	if unique {
		sort.Strings(pairs)
	}
	return strings.Join(pairs, "; ")
}

// normalizeAuthorization lowercases the case insensitive auth scheme and trims
// the surrounding space. The credentials are kept as sent.
func normalizeAuthorization(value string) string {
	value = strings.TrimSpace(value)
	scheme, credentials, found := strings.Cut(value, " ")
	if !found {
		return value
	}
	return strings.ToLower(scheme) + " " + strings.TrimSpace(credentials)
}
