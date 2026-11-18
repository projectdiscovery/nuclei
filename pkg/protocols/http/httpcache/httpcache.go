// Package httpcache provides RFC 9111 compliant HTTP response caching for nuclei.
// It wraps http.RoundTripper to cache responses based on standard HTTP caching headers.
package httpcache

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"go.dw1.io/x/net/http/cache"
)

var (
	cacheMu sync.Mutex
	shared  *cache.Transport
)

// getCache returns the shared cache. The first call, and the first after
// Close, loads it from the snapshot that Close saved.
func getCache() *cache.Transport {
	cacheMu.Lock()

	defer cacheMu.Unlock()
	if shared == nil {
		shared = openCache(snapshotPath())
	}

	return shared
}

// Close saves the shared cache to its snapshot and releases it. Safe if the
// cache was never opened.
func Close() {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if shared == nil {
		return
	}

	if err := saveSnapshot(shared, snapshotPath()); err != nil {
		gologger.Warning().Msgf("HTTP cache: could not save snapshot: %s", err)
	}

	stats := shared.Stats()
	gologger.Verbose().Msgf(
		"HTTP cache: %d hits, %d revalidated, %d misses, %d bypassed, %d stored or loaded, %d evicted, %d dropped",
		stats.Hits, stats.Revalidations, stats.Misses, stats.Bypasses, stats.Stores, stats.Evictions, stats.Drops)

	shared = nil
}

// NewTransportWrapper returns a function that wraps an [http.RoundTripper] with
// caching.
//
// This is designed to be used with retryablehttp's WrapTransport option.
func NewTransportWrapper() func(http.RoundTripper) http.RoundTripper {
	c := getCache()

	// Within one engine, the per-host clients' transports have the same TLS,
	// proxy, and compression settings. Nuclei accepts that the clients
	// sharing the cache still break some of WithNext's requirements:
	//   - Clients pinned to different IPs for one hostname reach different
	//     servers, yet one IP's response answers the same URL for the others.
	//   - SDK engines with different proxy or TLS options share the cache,
	//     which is process-wide.
	// Requests that carry Authorization, Cookie, or Origin skip the cache.
	// Those fields are not part of the cache key, so storing one of them
	// would let a later request without those credentials reuse the response.
	return func(rt http.RoundTripper) http.RoundTripper {
		return newCachingTransport(c, rt)
	}
}

// transport sends requests through a cache.Transport that shares the shared
// cache's stored responses.
type transport struct {
	cache *cache.Transport
	next  http.RoundTripper
}

// originContact records whether RoundTrip reached the next RoundTripper.
// A pure cache hit leaves origin false. The cache clones the request and
// keeps this pointer in the context, including on revalidation.
type originContact struct {
	origin    bool
	setCookie []string
}

type originContactKey struct{}

// originMarker sets origin before the request reaches the live transport.
type originMarker struct {
	next http.RoundTripper
}

func (m originMarker) RoundTrip(req *http.Request) (*http.Response, error) {
	contact, _ := req.Context().Value(originContactKey{}).(*originContact)
	if contact != nil {
		contact.origin = true
	}
	resp, err := m.next.RoundTrip(req)
	if err != nil || resp == nil || contact == nil {
		return resp, err
	}
	// The cache stores the header map it is given. Drop Set-Cookie before that
	// copy so one client's jar is not installed into another's. The caller gets
	// the values back on a header map the cache does not retain.
	contact.setCookie = takeSetCookies(resp.Header)
	return resp, nil
}

func newCachingTransport(base *cache.Transport, next http.RoundTripper) *transport {
	return &transport{cache: base.WithNext(originMarker{next: next}), next: next}
}

// carriesIdentity reports whether req has a credential or browser-origin
// field the cache key does not include. Header keys are compared
// case-insensitively because a builder can store a non-canonical key.
func carriesIdentity(req *http.Request) bool {
	return headerHas(req.Header, "Authorization") || headerHas(req.Header, "Cookie") || headerHas(req.Header, "Origin")
}

func headerHas(h http.Header, name string) bool {
	for key, values := range h {
		if len(values) > 0 && strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func nonCanonicalHeader(h http.Header) bool {
	for key := range h {
		if key != http.CanonicalHeaderKey(key) {
			return true
		}
	}
	return false
}

func takeSetCookies(h http.Header) []string {
	var cookies []string
	for key, values := range h {
		if strings.EqualFold(key, "Set-Cookie") {
			cookies = append(cookies, values...)
			delete(h, key)
		}
	}
	return cookies
}

// ServedFromCache reports whether resp was answered from stored data without
// a request to the origin. Revalidated responses contacted the origin and
// report false.
func ServedFromCache(resp *http.Response) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	contact, ok := resp.Request.Context().Value(originContactKey{}).(*originContact)
	return ok && contact != nil && !contact.origin
}

// ContactedOrigin reports whether a completed attempt should move the
// per-host backoff governor. Project-file hits leave sent false. A pure
// HTTP cache hit leaves ServedFromCache true.
func ContactedOrigin(sent bool, resp *http.Response) bool {
	return sent && !ServedFromCache(resp)
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	getOrHead := req.Method == "" || req.Method == http.MethodGet || req.Method == http.MethodHead
	// Credentialed and non-canonical GET/HEAD requests skip the cache. Unsafe
	// methods still go through it so a successful write invalidates the URI.
	if getOrHead && (carriesIdentity(req) || nonCanonicalHeader(req.Header)) {
		return t.next.RoundTrip(req)
	}

	switch req.Method {
	case "", http.MethodGet, http.MethodHead:
		// Request building installs an empty httpbody.Body on requests without
		// a body. The cache bypasses a GET or HEAD whose Body is neither nil nor
		// NoBody, since its length is unknown. Only for these methods does Go
		// send both bodies the same way: a POST with the empty httpbody.Body
		// goes chunked, and with NoBody it gets Content-Length: 0.
		if body, ok := req.Body.(*httpbody.Body); ok && body.Len() == 0 {
			cloned := req.Clone(req.Context())
			cloned.Body = http.NoBody
			req = cloned
		}
	}

	contact := &originContact{}
	req = req.Clone(context.WithValue(req.Context(), originContactKey{}, contact))
	resp, err := t.cache.RoundTrip(req)
	if err != nil || resp == nil || len(contact.setCookie) == 0 {
		return resp, err
	}
	restored := resp.Header.Clone()
	restored["Set-Cookie"] = contact.setCookie
	resp.Header = restored
	return resp, nil
}

func snapshotPath() string {
	return filepath.Join(config.DefaultConfig.GetCacheDir(), "httpcache", "snapshot")
}

// openCache returns a new cache holding the responses in the snapshot at path.
// The cache validates each loaded response with the origin before its first
// use. Requests go through the Transports that WithNext returns, never through
// the one openCache returns, so its next RoundTripper doesn't matter.
func openCache(path string) *cache.Transport {
	c, err := cache.New(nil)
	if err != nil {
		// New fails only for invalid options, and none are passed.
		panic(err)
	}

	if err := loadSnapshot(c, path); err != nil {
		gologger.Warning().Msgf("HTTP cache: could not load snapshot %q: %s", path, err)
	}

	gologger.Verbose().Msgf("HTTP cache initialized (snapshot %q)", path)

	return c
}

func loadSnapshot(c *cache.Transport, path string) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	return c.Load(f)
}

// saveSnapshot writes c to path through a temporary file, so that a nuclei
// process starting meanwhile never loads a partial snapshot.
func saveSnapshot(c *cache.Transport, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// CreateTemp creates the file with mode 0600. The snapshot holds whole
	// responses, including those to requests with Authorization or Cookie.
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}

	err = errors.Join(c.Save(tmp), tmp.Close())
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}

	if err != nil {
		_ = os.Remove(tmp.Name())
	}

	return err
}
