package server

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

type requestDeduplicator struct {
	hashes map[string]struct{}
	lock   *sync.RWMutex
}

func newRequestDeduplicator() *requestDeduplicator {
	return &requestDeduplicator{
		hashes: make(map[string]struct{}),
		lock:   &sync.RWMutex{},
	}
}

func (r *requestDeduplicator) isDuplicate(req *types.RequestResponse) bool {
	hash, err := hashRequest(req)
	if err != nil {
		return false
	}

	r.lock.RLock()
	_, ok := r.hashes[hash]
	r.lock.RUnlock()
	if ok {
		return true
	}

	r.lock.Lock()
	r.hashes[hash] = struct{}{}
	r.lock.Unlock()
	return false
}

func hashRequest(req *types.RequestResponse) (string, error) {
	normalizedURL, err := normalizeURL(req.URL.URL)
	if err != nil {
		return "", err
	}

	var hashContent strings.Builder
	hashContent.WriteString(req.Request.Method)
	hashContent.WriteString(normalizedURL)

	headers := sortedNonDynamicHeaders(req.Request.Headers)
	for _, header := range headers {
		hashContent.WriteString(header.Key)
		hashContent.WriteString(header.Value)
	}

	if len(req.Request.Body) > 0 {
		hashContent.Write([]byte(req.Request.Body))
	}

	// Calculate the SHA256 hash
	hash := sha256.Sum256([]byte(hashContent.String()))
	return hex.EncodeToString(hash[:]), nil
}

func normalizeURL(u *url.URL) (string, error) {
	query := u.Query()
	sortedQuery := make(url.Values)
	for k, v := range query {
		sort.Strings(v)
		sortedQuery[k] = v
	}
	u.RawQuery = sortedQuery.Encode()

	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

type header struct {
	Key   string
	Value string
}

func sortedNonDynamicHeaders(headers mapsutil.OrderedMap[string, string]) []header {
	var result []header
	headers.Iterate(func(k, v string) bool {
		if !dynamicHeaders[strings.ToLower(k)] {
			result = append(result, header{Key: k, Value: v})
		}
		return true
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].Key < result[j].Key
	})
	return result
}
