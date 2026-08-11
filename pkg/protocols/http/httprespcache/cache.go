// Package httprespcache is a scan-scoped in-memory cache for safe HTTP GET/HEAD
// responses. It lets tech fingerprinting and templates share the same RTT.
package httprespcache

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Cache stores response snapshots keyed by METHOD + URL.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	disabled atomic.Bool
	hits     atomic.Uint64
	misses   atomic.Uint64
	stores   atomic.Uint64
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

// New returns an empty cache.
func New() *Cache {
	return &Cache{entries: make(map[string]*Entry)}
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

// Key builds a cache key for a method and absolute URL.
func Key(method, rawURL string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	rawURL = strings.TrimSpace(rawURL)
	return method + " " + rawURL
}

// KeyFromRequest builds a key from an http.Request.
func KeyFromRequest(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return Key(req.Method, req.URL.String())
}

// CacheableRequest reports whether the request is safe to cache/serve.
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
func (c *Cache) Set(key string, resp *http.Response, body []byte) {
	if !c.Enabled() || key == "" || resp == nil {
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
		ContentLength: int64(len(body)),
	}
	c.mu.Lock()
	c.entries[key] = ent
	c.mu.Unlock()
	c.stores.Add(1)
}

// SeedHTTP stores a response from an already-buffered fingerprint/probe.
func (c *Cache) SeedHTTP(method, rawURL string, resp *http.Response, body []byte) {
	c.Set(Key(method, rawURL), resp, body)
}

// Stats returns hit/miss/store counters.
func (c *Cache) Stats() (hits, misses, stores uint64) {
	if c == nil {
		return 0, 0, 0
	}
	return c.hits.Load(), c.misses.Load(), c.stores.Load()
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
