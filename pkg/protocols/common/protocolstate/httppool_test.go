package protocolstate

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

type fakeTransport struct {
	closedIdle atomic.Int64
}

func (f *fakeTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (f *fakeTransport) CloseIdleConnections()                           { f.closedIdle.Add(1) }

func newFakeClient(rt http.RoundTripper) (*retryablehttp.Client, error) {
	return retryablehttp.NewWithHTTPClient(&http.Client{Transport: rt}, retryablehttp.DefaultOptionsSingle), nil
}

func TestHTTPPool_ClientCaching(t *testing.T) {
	pool := NewHTTPPool(time.Minute, time.Minute)

	createTransport := func() (http.RoundTripper, error) { return &fakeTransport{}, nil }

	c1, err := pool.GetOrCreateClient("client-a", "transport-a", createTransport, newFakeClient)
	require.NoError(t, err)
	c2, err := pool.GetOrCreateClient("client-a", "transport-a", createTransport, newFakeClient)
	require.NoError(t, err)
	require.Same(t, c1, c2, "same client key must hit the cache")

	cached, ok := pool.GetClient("client-a")
	require.True(t, ok)
	require.Same(t, c1, cached)
}

func TestHTTPPool_TransportSharedAcrossClients(t *testing.T) {
	pool := NewHTTPPool(time.Minute, time.Minute)

	var created atomic.Int64
	createTransport := func() (http.RoundTripper, error) {
		created.Add(1)
		return &fakeTransport{}, nil
	}

	c1, err := pool.GetOrCreateClient("client-a", "transport-shared", createTransport, newFakeClient)
	require.NoError(t, err)
	c2, err := pool.GetOrCreateClient("client-b", "transport-shared", createTransport, newFakeClient)
	require.NoError(t, err)

	require.NotSame(t, c1, c2, "different client keys must produce different clients")
	require.Same(t, c1.HTTPClient.Transport, c2.HTTPClient.Transport,
		"clients with the same transport key must share one transport")
	require.EqualValues(t, 1, created.Load(), "transport must be created exactly once")
}

func TestHTTPPool_SingleflightCreation(t *testing.T) {
	pool := NewHTTPPool(time.Minute, time.Minute)

	var transportsCreated, clientsCreated atomic.Int64
	createTransport := func() (http.RoundTripper, error) {
		transportsCreated.Add(1)
		time.Sleep(10 * time.Millisecond) // widen the race window
		return &fakeTransport{}, nil
	}
	createClient := func(rt http.RoundTripper) (*retryablehttp.Client, error) {
		clientsCreated.Add(1)
		return newFakeClient(rt)
	}

	const workers = 32
	clients := make([]*retryablehttp.Client, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := pool.GetOrCreateClient("client-key", "transport-key", createTransport, createClient)
			require.NoError(t, err)
			clients[idx] = c
		}(i)
	}
	wg.Wait()

	for i := 1; i < workers; i++ {
		require.Same(t, clients[0], clients[i], "all concurrent callers must receive the same client")
	}
	require.EqualValues(t, 1, transportsCreated.Load(), "singleflight must build exactly one transport")
	require.EqualValues(t, 1, clientsCreated.Load(), "singleflight must build exactly one client")
}

func TestHTTPPool_EvictionClosesIdleConnections(t *testing.T) {
	pool := NewHTTPPool(10*time.Millisecond, time.Hour)

	ft := &fakeTransport{}
	_, err := pool.GetOrCreateClient("client-a", "transport-a",
		func() (http.RoundTripper, error) { return ft, nil }, newFakeClient)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)
	pool.evictInactive()

	_, ok := pool.GetClient("client-a")
	require.False(t, ok, "idle client must be evicted")
	require.EqualValues(t, 1, ft.closedIdle.Load(), "evicted transport must close idle connections")
}

func TestHTTPPool_ActiveClientKeepsTransportAlive(t *testing.T) {
	pool := NewHTTPPool(50*time.Millisecond, time.Hour)

	ft := &fakeTransport{}
	_, err := pool.GetOrCreateClient("client-a", "transport-a",
		func() (http.RoundTripper, error) { return ft, nil }, newFakeClient)
	require.NoError(t, err)

	// keep touching the client; the shared transport must stay alive too
	for i := 0; i < 5; i++ {
		time.Sleep(20 * time.Millisecond)
		_, ok := pool.GetClient("client-a")
		require.True(t, ok)
		pool.evictInactive()
	}
	require.EqualValues(t, 0, ft.closedIdle.Load(), "active transport must not be evicted")
}

// BenchmarkHTTPPool_GetClientParallel measures the lock-free hit path under
// contention; compare with BenchmarkSyncLockMap_GetParallel (the previous
// pool backing) to see the effect of removing per-hit mutex acquisitions.
func BenchmarkHTTPPool_GetClientParallel(b *testing.B) {
	pool := NewHTTPPool(90*time.Second, 30*time.Second)
	_, err := pool.GetOrCreateClient("key", "tkey",
		func() (http.RoundTripper, error) { return &fakeTransport{}, nil }, newFakeClient)
	require.NoError(b, err)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := pool.GetClient("key"); !ok {
				b.Fatal("cache miss")
			}
		}
	})
}

// BenchmarkSyncLockMap_GetParallel benchmarks the previous pool backing
// (mapsutil.SyncLockMap with eviction) for comparison.
func BenchmarkSyncLockMap_GetParallel(b *testing.B) {
	m := mapsutil.NewSyncLockMap(
		mapsutil.WithEviction[string, *retryablehttp.Client](90*time.Second, 30*time.Second),
	)
	client, err := newFakeClient(&fakeTransport{})
	require.NoError(b, err)
	require.NoError(b, m.Set("key", client))

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := m.Get("key"); !ok {
				b.Fatal("cache miss")
			}
		}
	})
}

func TestHTTPPool_Close(t *testing.T) {
	pool := NewHTTPPool(time.Minute, time.Minute)

	ft := &fakeTransport{}
	_, err := pool.GetOrCreateClient("client-a", "transport-a",
		func() (http.RoundTripper, error) { return ft, nil }, newFakeClient)
	require.NoError(t, err)

	pool.Close()

	_, ok := pool.GetClient("client-a")
	require.False(t, ok, "Close must drop all clients")
	require.EqualValues(t, 1, ft.closedIdle.Load(), "Close must close idle connections on transports")
}
