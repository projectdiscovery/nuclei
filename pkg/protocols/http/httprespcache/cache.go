// Package httprespcache is a scan-scoped in-memory cache for safe HTTP GET/HEAD
// responses. It lets tech fingerprinting and templates share the same RTT.
package httprespcache

import (
	"bytes"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cespare/xxhash"
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
	// Entry cap sized above a typical per-host unique GET set; the byte cap below
	// is the real memory bound, so a larger entry cap cannot grow memory.
	defaultMaxEntries = 16384
	defaultMaxBytes   = 64 << 20 // 64 MiB of retained responses (key, headers and body)
	// defaultMaxSeen bounds the (owner, key) record: about 16 bytes per pair.
	defaultMaxSeen = 1 << 20
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

	// seen records every (owner, key) pair that has been looked up or stored,
	// as a hash. A pair already seen is never served from the cache: a template
	// that repeats a request means it (state changes, race checks,
	// request-and-compare), so the repeat must reach the server even when another
	// template stored a response in between. When the record is full the cache
	// stops serving hits instead of forgetting pairs.
	seen    map[uint64]struct{}
	maxSeen int
}

// Entry is a reusable response snapshot.
type Entry struct {
	// Owner identifies who stored the entry (a template ID). It is never served
	// back to the same owner: a template that repeats its own request means it
	// (state changes, race checks, request-and-compare), so that repeat must
	// reach the server.
	Owner         string
	StatusCode    int
	Status        string
	Proto         string
	ProtoMajor    int
	ProtoMinor    int
	Header        http.Header
	Body          []byte
	ContentLength int64
	// size is what the entry is charged against maxBytes: key, headers and body.
	size int64
}

// New returns an empty cache with default memory bounds.
func New() *Cache {
	return &Cache{
		entries:    make(map[string]*Entry),
		maxEntries: defaultMaxEntries,
		maxBytes:   defaultMaxBytes,
		seen:       make(map[uint64]struct{}),
		maxSeen:    defaultMaxSeen,
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
	// A GET/HEAD carrying a real payload is excluded: the body is part of the
	// request identity but not of the cache key. An empty body is not.
	// Every GET/HEAD built here goes through retryablehttp, which computes
	// ContentLength from the buffered body, so ContentLength == 0 proves the
	// body carries no bytes even when the reader itself is non-nil.
	if req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
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
		case "host":
			// net/http never writes Header["Host"] on the wire; it sends
			// req.Host or req.URL.Host. A Host header that repeats the target
			// host therefore changes nothing. A different one is a deliberate
			// Host override and must not share a cached response.
			if !sameHost(req.Header.Get("Host"), req.URL) {
				return false
			}
		case "cache-control", "pragma":
			// Explicit cache directives: never serve from the scan cache.
			return false
		default:
			return false
		}
	}
	return true
}

// sameHost reports whether host names the same authority as u, ignoring the
// default port for the URL scheme.
func sameHost(host string, u *url.URL) bool {
	if host == "" || u == nil {
		return false
	}
	return strings.EqualFold(canonicalHost(host, u.Scheme), canonicalHost(u.Host, u.Scheme))
}

func canonicalHost(host, scheme string) string {
	host = strings.TrimSpace(host)
	defaultPort := ""
	switch strings.ToLower(scheme) {
	case "http":
		defaultPort = ":80"
	case "https":
		defaultPort = ":443"
	}
	if defaultPort != "" {
		host = strings.TrimSuffix(host, defaultPort)
	}
	return host
}

// JarAllows reports whether the cookie jar would attach no cookies to u.
// A jar is created for every input, so its mere presence must not disable the
// cache. What matters is whether cookies would change the request or response:
// if the jar has nothing for this URL, a response captured without cookies is
// equivalent to a fresh one.
func JarAllows(jar *cookiejar.Jar, u *url.URL) bool {
	if jar == nil {
		return true
	}
	if u == nil {
		return false
	}
	return len(jar.Cookies(u)) == 0
}

// ResponseSetsCookie reports whether resp carries Set-Cookie. Such responses are
// never stored, so serving from cache can never hide a jar update.
func ResponseSetsCookie(resp *http.Response) bool {
	return resp != nil && len(resp.Header.Values("Set-Cookie")) > 0
}

// Get returns a fresh *http.Response (new Body reader) or nil on miss.
// req is attached as Response.Request so downstream dump/curl code works.
// An entry stored by owner is not served back to owner; see Entry.Owner.
func (c *Cache) Get(key, owner string, req *http.Request) *http.Response {
	if !c.Enabled() || key == "" {
		return nil
	}
	c.mu.Lock()
	firstLook := c.markSeen(owner, key)
	ent, ok := c.entries[key]
	c.mu.Unlock()
	if !firstLook || !ok || ent == nil || (owner != "" && ent.Owner == owner) {
		c.misses.Add(1)
		return nil
	}
	c.hits.Add(1)
	return ent.toResponse(req)
}

// Set stores a snapshot for key. body should already be fully read.
// Entries that would exceed the scan-wide budget are skipped.
func (c *Cache) Set(key, owner string, resp *http.Response, body []byte) {
	if !c.Enabled() || key == "" || resp == nil {
		return
	}
	bodyLen := int64(len(body))
	size := int64(len(key)) + headerSize(resp.Header) + bodyLen
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markSeen(owner, key)

	if old, ok := c.entries[key]; ok {
		c.curBytes -= old.size
		delete(c.entries, key)
	} else if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.skipped.Add(1)
		return
	}
	if c.maxBytes > 0 && c.curBytes+size > c.maxBytes {
		c.skipped.Add(1)
		return
	}

	ent := &Entry{
		Owner:         owner,
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        resp.Header.Clone(),
		Body:          append([]byte(nil), body...),
		ContentLength: bodyLen,
		size:          size,
	}
	c.entries[key] = ent
	c.curBytes += size
	c.stores.Add(1)
}

// SeedHTTP stores a fingerprint/probe response under the request's full key
// (method + URL + representation headers). readLimit is the most the probe
// read of the body; see CompleteBody.
func (c *Cache) SeedHTTP(req *http.Request, resp *http.Response, body []byte, readLimit int64) {
	if !CacheableRequest(req) || !CompleteBody(body, readLimit) {
		return
	}
	c.Set(KeyFromRequest(req), "", resp, body)
}

// CompleteBody reports whether body was read to its end under readLimit. A body
// that fills the limit may be cut short, and a reader with a larger limit
// (another template's max-size) would then match against the cut copy, so such
// a body must not be cached. A readLimit of zero or less means no limit.
func CompleteBody(body []byte, readLimit int64) bool {
	return readLimit <= 0 || int64(len(body)) < readLimit
}

// Reset drops every entry and the counters, keeping the cache usable. It lets a
// long-lived engine reuse one cache instance while scoping its content to one
// scan.
func (c *Cache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.curBytes = 0
	c.seen = make(map[uint64]struct{})
	c.mu.Unlock()
	c.hits.Store(0)
	c.misses.Store(0)
	c.stores.Store(0)
	c.skipped.Store(0)
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

// markSeen records the (owner, key) pair and reports whether this is its first
// sighting. It reports false when the record is full, so nothing is served
// that could not be remembered. An empty owner is not tracked. Must hold c.mu.
func (c *Cache) markSeen(owner, key string) bool {
	if owner == "" {
		return true
	}
	if c.seen == nil {
		c.seen = make(map[uint64]struct{})
	}
	h := xxhash.Sum64String(owner + "\x00" + key)
	if _, ok := c.seen[h]; ok {
		return false
	}
	if c.maxSeen > 0 && len(c.seen) >= c.maxSeen {
		return false
	}
	c.seen[h] = struct{}{}
	return true
}

func headerSize(h http.Header) int64 {
	var n int64
	for k, vs := range h {
		for _, v := range vs {
			n += int64(len(k) + len(v) + 4) // "k: v\r\n"
		}
	}
	return n
}

// ReplayableEncoding reports whether a response can be replayed from its
// decoded body with identical results. The response chain decodes the body by
// its Content-Encoding header, and a cache hit keeps that header (templates may
// match on it), so a hit is decoded again. That is harmless only when the
// second decode fails at once and falls back to the same bytes: no encoding, or
// gzip whose decoded body does not itself start with the gzip magic bytes.
// Other encodings (deflate, br, zstd) can fail mid-read or decode twice, so
// they are not cached.
func ReplayableEncoding(h http.Header, decodedBody []byte) bool {
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))) {
	case "", "identity":
		return true
	case "gzip":
		return len(decodedBody) < 2 || decodedBody[0] != 0x1f || decodedBody[1] != 0x8b
	default:
		return false
	}
}

// StoredStatus reports whether a response status may be cached. Transient
// failures (408, 429, 5xx) are not: a later request may find the server
// recovered, and serving the failure would hide that.
func StoredStatus(code int) bool {
	return code != http.StatusRequestTimeout && code != http.StatusTooManyRequests && code < http.StatusInternalServerError
}
