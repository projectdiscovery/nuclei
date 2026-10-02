// Package httprespcache is a scan-scoped in-memory cache for safe HTTP GET/HEAD
// responses. It lets tech fingerprinting and templates share the same RTT.
package httprespcache

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// representationHeaderNames are folded into the cache key so two requests
// that differ only in content-negotiation / UA identity cannot share a body.
var representationHeaderNames = []string{
	"accept",
	"accept-encoding",
	"accept-language",
	"user-agent",
}

const (
	defaultMaxEntries = 4096
	defaultMaxBytes   = 64 << 20 // 64 MiB of retained response bodies
)

// Cache stores response snapshots keyed by METHOD + URL + representation headers.
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*Entry
	disabled   atomic.Bool
	hits       atomic.Uint64
	misses     atomic.Uint64
	stores     atomic.Uint64
	skipped    atomic.Uint64
	maxEntries int
	maxBytes   int64
	curBytes   int64
}

// Entry is a reusable response snapshot.
type Entry struct {
	StatusCode    int
	Status        string
	Proto         string
	ProtoMajor    int
	ProtoMinor    int
	Header        http.Header
	Body          []byte
	ContentLength int64
}

// New returns an empty cache with default memory bounds.
func New() *Cache {
	return &Cache{
		entries:    make(map[string]*Entry),
		maxEntries: defaultMaxEntries,
		maxBytes:   defaultMaxBytes,
	}
}

// Disable stops all Get/Set operations (used when -tf is set but the planner
// skips tech filtering, so default scan semantics stay unchanged).
func (c *Cache) Disable() {
	if c != nil {
		c.disabled.Store(true)
	}
}

// Enabled reports whether the cache is accepting Get/Set.
func (c *Cache) Enabled() bool {
	return c != nil && !c.disabled.Load()
}

// Key builds a cache key for a method and absolute URL (no header identity).
func Key(method, rawURL string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	rawURL = strings.TrimSpace(rawURL)
	return method + " " + rawURL
}

// KeyFromRequest builds a key from an http.Request, including representation
// headers (UA / Accept*) so distinct content-negotiation contexts do not collide.
func KeyFromRequest(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	base := Key(req.Method, req.URL.String())
	parts := make([]string, 0, len(representationHeaderNames))
	for _, name := range representationHeaderNames {
		vals := req.Header.Values(name)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, name+":"+strings.Join(vals, ","))
	}
	if len(parts) == 0 {
		return base
	}
	sort.Strings(parts)
	return base + " |" + strings.Join(parts, "|")
}

// CacheableRequest reports whether the request is safe to cache/serve.
// Requests with auth, cookies, Host override, Cache-Control/Pragma, or any
// non-allowlisted header are excluded so they cannot reuse another context.
func CacheableRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	method := strings.ToUpper(req.Method)
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if req.Body != nil && req.Body != http.NoBody {
		return false
	}
	if req.Host != "" && req.URL.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return false
	}
	for k := range req.Header {
		switch strings.ToLower(k) {
		case "user-agent", "accept", "accept-language", "accept-encoding",
			"connection", "upgrade-insecure-requests":
			continue
		case "cache-control", "pragma":
			// Explicit cache directives: never serve from the scan cache.
			return false
		default:
			return false
		}
	}
	return true
}

// Get returns a fresh *http.Response (new Body reader) or nil on miss.
// req is attached as Response.Request so downstream dump/curl code works.
func (c *Cache) Get(key string, req *http.Request) *http.Response {
	if !c.Enabled() || key == "" {
		return nil
	}
	c.mu.RLock()
	ent, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || ent == nil {
		c.misses.Add(1)
		return nil
	}
	c.hits.Add(1)
	return ent.toResponse(req)
}

// Set stores a snapshot for key. body should already be fully read.
// Entries that would exceed the scan-wide budget are skipped.
func (c *Cache) Set(key string, resp *http.Response, body []byte) {
	if !c.Enabled() || key == "" || resp == nil {
		return
	}
	bodyLen := int64(len(body))
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.entries[key]; ok {
		c.curBytes -= old.ContentLength
		delete(c.entries, key)
	} else if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.skipped.Add(1)
		return
	}
	if c.maxBytes > 0 && c.curBytes+bodyLen > c.maxBytes {
		c.skipped.Add(1)
		return
	}

	ent := &Entry{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        resp.Header.Clone(),
		Body:          append([]byte(nil), body...),
		ContentLength: bodyLen,
	}
	c.entries[key] = ent
	c.curBytes += bodyLen
	c.stores.Add(1)
}

// SeedHTTP stores a fingerprint/probe response under the request's full key
// (method + URL + representation headers).
func (c *Cache) SeedHTTP(req *http.Request, resp *http.Response, body []byte) {
	if !CacheableRequest(req) {
		return
	}
	c.Set(KeyFromRequest(req), resp, body)
}

// Stats returns hit/miss/store counters.
func (c *Cache) Stats() (hits, misses, stores uint64) {
	if c == nil {
		return 0, 0, 0
	}
	return c.hits.Load(), c.misses.Load(), c.stores.Load()
}

// Len returns the number of cached entries (tests).
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (e *Entry) toResponse(req *http.Request) *http.Response {
	return &http.Response{
		Status:        e.Status,
		StatusCode:    e.StatusCode,
		Proto:         e.Proto,
		ProtoMajor:    e.ProtoMajor,
		ProtoMinor:    e.ProtoMinor,
		Header:        e.Header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(e.Body)),
		ContentLength: e.ContentLength,
		Request:       req,
	}
}
