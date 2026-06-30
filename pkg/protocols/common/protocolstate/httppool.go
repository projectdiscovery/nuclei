package protocolstate

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/sync/singleflight"
)

// closeIdler is implemented by transports that can drop idle connections.
type closeIdler interface{ CloseIdleConnections() }

// httpTransportEntry tracks a pooled transport and its last access time.
type httpTransportEntry struct {
	rt         http.RoundTripper
	lastAccess atomic.Int64 // unix nanoseconds
}

func (e *httpTransportEntry) touch(now int64) { e.lastAccess.Store(now) }

// httpClientEntry tracks a pooled client, the transport it shares and its
// last access time.
type httpClientEntry struct {
	client     *retryablehttp.Client
	transport  *httpTransportEntry
	lastAccess atomic.Int64 // unix nanoseconds
}

func (e *httpClientEntry) touch(now int64) {
	e.lastAccess.Store(now)
	if e.transport != nil {
		// keep the shared transport alive while any of its clients is active
		e.transport.touch(now)
	}
}

// HTTPPool is a two-level cache for retryablehttp clients and the
// http.RoundTripper transports they share.
//
// Design goals (hot path = one lookup per outgoing request):
//   - lock-free cache hits: sync.Map reads plus atomic last-access updates,
//     no global mutex acquisition per request
//   - singleflight creation: concurrent first requests to the same key build
//     exactly one client/transport instead of N-1 orphans holding sockets
//   - transport/client split: client-level settings (redirect policy, cookie
//     jar, timeout) get their own cheap client wrapper while sharing one
//     transport (and therefore one connection pool) per host
//   - eviction closes connections: idle transports get CloseIdleConnections()
//     instead of being silently dropped for the GC to find
type HTTPPool struct {
	clients     sync.Map // string -> *httpClientEntry
	transports  sync.Map // string -> *httpTransportEntry
	clientSF    singleflight.Group
	transportSF singleflight.Group

	inactivity      time.Duration
	cleanupInterval time.Duration
	lastCleanup     atomic.Int64 // unix nanoseconds
	cleanupRunning  atomic.Bool
}

// NewHTTPPool creates a pool whose entries are evicted after the given
// inactivity duration, checked lazily at most once per cleanupInterval.
func NewHTTPPool(inactivity, cleanupInterval time.Duration) *HTTPPool {
	p := &HTTPPool{
		inactivity:      inactivity,
		cleanupInterval: cleanupInterval,
	}
	p.lastCleanup.Store(time.Now().UnixNano())
	return p
}

// GetClient returns a cached client for the key, refreshing its eviction
// timestamp. The hit path performs no locking.
func (p *HTTPPool) GetClient(key string) (*retryablehttp.Client, bool) {
	v, ok := p.clients.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(*httpClientEntry)
	entry.touch(time.Now().UnixNano())
	p.maybeCleanup()
	return entry.client, true
}

// GetOrCreateClient returns the cached client for clientKey or builds it
// exactly once (singleflight) using a transport shared via transportKey.
func (p *HTTPPool) GetOrCreateClient(
	clientKey, transportKey string,
	createTransport func() (http.RoundTripper, error),
	createClient func(rt http.RoundTripper) (*retryablehttp.Client, error),
) (*retryablehttp.Client, error) {
	if client, ok := p.GetClient(clientKey); ok {
		return client, nil
	}
	v, err, _ := p.clientSF.Do(clientKey, func() (interface{}, error) {
		if existing, ok := p.clients.Load(clientKey); ok {
			return existing.(*httpClientEntry), nil
		}
		tEntry, err := p.getOrCreateTransportEntry(transportKey, createTransport)
		if err != nil {
			return nil, err
		}
		client, err := createClient(tEntry.rt)
		if err != nil {
			return nil, err
		}
		entry := &httpClientEntry{client: client, transport: tEntry}
		entry.touch(time.Now().UnixNano())
		p.clients.Store(clientKey, entry)
		return entry, nil
	})
	if err != nil {
		return nil, err
	}
	entry := v.(*httpClientEntry)
	entry.touch(time.Now().UnixNano())
	return entry.client, nil
}

// GetOrCreateTransport returns the shared transport for the key, building it
// exactly once. Used directly by callers that need an uncached client (e.g.
// explicit per-request cookie jars) but still want pooled connections.
func (p *HTTPPool) GetOrCreateTransport(key string, create func() (http.RoundTripper, error)) (http.RoundTripper, error) {
	entry, err := p.getOrCreateTransportEntry(key, create)
	if err != nil {
		return nil, err
	}
	return entry.rt, nil
}

func (p *HTTPPool) getOrCreateTransportEntry(key string, create func() (http.RoundTripper, error)) (*httpTransportEntry, error) {
	if v, ok := p.transports.Load(key); ok {
		entry := v.(*httpTransportEntry)
		entry.touch(time.Now().UnixNano())
		return entry, nil
	}
	v, err, _ := p.transportSF.Do(key, func() (interface{}, error) {
		if existing, ok := p.transports.Load(key); ok {
			return existing.(*httpTransportEntry), nil
		}
		rt, err := create()
		if err != nil {
			return nil, err
		}
		entry := &httpTransportEntry{rt: rt}
		entry.touch(time.Now().UnixNano())
		p.transports.Store(key, entry)
		return entry, nil
	})
	if err != nil {
		return nil, err
	}
	entry := v.(*httpTransportEntry)
	entry.touch(time.Now().UnixNano())
	return entry, nil
}

// maybeCleanup spawns a single background eviction pass if the cleanup
// interval has elapsed. Uses CAS so only one goroutine wins.
func (p *HTTPPool) maybeCleanup() {
	if p.inactivity <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := p.lastCleanup.Load()
	if now-last < p.cleanupInterval.Nanoseconds() {
		return
	}
	if !p.lastCleanup.CompareAndSwap(last, now) {
		return
	}
	if !p.cleanupRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer p.cleanupRunning.Store(false)
		p.evictInactive()
	}()
}

// evictInactive drops clients and transports idle for longer than the
// inactivity window. Evicted transports get their idle connections closed
// immediately instead of waiting for the GC / IdleConnTimeout.
func (p *HTTPPool) evictInactive() {
	deadline := time.Now().Add(-p.inactivity).UnixNano()

	p.clients.Range(func(k, v interface{}) bool {
		if v.(*httpClientEntry).lastAccess.Load() < deadline {
			p.clients.Delete(k)
		}
		return true
	})
	// Transports are touched whenever one of their clients is touched, so a
	// transport only goes idle once all clients sharing it are idle too.
	p.transports.Range(func(k, v interface{}) bool {
		entry := v.(*httpTransportEntry)
		if entry.lastAccess.Load() < deadline {
			p.transports.Delete(k)
			if ci, ok := entry.rt.(closeIdler); ok {
				ci.CloseIdleConnections()
			}
		}
		return true
	})
}

// Close drops all cached clients and transports, closing idle connections so
// no transport goroutines linger after shutdown.
func (p *HTTPPool) Close() {
	p.clients.Range(func(k, _ interface{}) bool {
		p.clients.Delete(k)
		return true
	})
	p.transports.Range(func(k, v interface{}) bool {
		p.transports.Delete(k)
		if ci, ok := v.(*httpTransportEntry).rt.(closeIdler); ok {
			ci.CloseIdleConnections()
		}
		return true
	})
}
