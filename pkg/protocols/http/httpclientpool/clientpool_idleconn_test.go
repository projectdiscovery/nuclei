package httpclientpool

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/retryablehttp-go"
)

// TestIdleConnPoolAllowsKeepAliveReuse is a regression test for the per-host
// idle connection pool being smaller than the concurrency that runs against a
// host.
//
// http.Transport closes a connection returned to a host whose idle pool is
// already full. When MaxIdleConnsPerHost was 4, a scan running templates
// concurrently against one host reused almost nothing: connections past the
// fourth were closed on return and the next request dialled again, so the
// target saw close to one TCP connection per HTTP request.
//
// The server counts accepted connections, which is what actually matters:
// connection churn is invisible in request counts but is what pays a TCP (and
// TLS) handshake per request and exhausts NAT port mappings.
func TestIdleConnPoolAllowsKeepAliveReuse(t *testing.T) {
	const (
		requests    = 400
		concurrency = 50
	)

	var accepted, arrived atomic.Int64

	// Hold the first `concurrency` requests inside the handler until all of
	// them have arrived, so the transport is genuinely forced to keep that
	// many connections open at once. Without this the requests could
	// serialise and the connection count would prove nothing.
	barrier := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(barrier) }) }
	// Safety valve: never hang the suite if fewer than `concurrency` requests
	// ever reach the handler.
	timer := time.AfterFunc(30*time.Second, release)
	defer timer.Stop()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if arrived.Add(1) >= concurrency {
			release()
		}
		<-barrier
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	opts := newTestOptions(t, "test-idle-conn-pool-reuse")
	opts.TemplateThreads = concurrency

	client, err := Get(opts, &Configuration{}, server.Listener.Addr().String())
	require.NoError(t, err)

	var succeeded atomic.Int64
	var errMu sync.Mutex
	var firstErr error

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			recordErr := func(err error) {
				errMu.Lock()
				defer errMu.Unlock()
				if firstErr == nil {
					firstErr = err
				}
			}

			req, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/path-%d", server.URL, i), nil)
			if err != nil {
				recordErr(err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				recordErr(err)
				return
			}
			// Drain and close so the connection is eligible for reuse.
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				_ = resp.Body.Close()
				recordErr(err)
				return
			}
			if err := resp.Body.Close(); err != nil {
				recordErr(err)
				return
			}
			succeeded.Add(1)
		}(i)
	}
	wg.Wait()

	// Without these the connection assertion is vacuous: zero successful
	// requests also means zero connections.
	require.NoError(t, firstErr, "requests must succeed for the connection count to mean anything")
	require.Equal(t, int64(requests), succeeded.Load(), "all requests must succeed")
	require.GreaterOrEqual(t, arrived.Load(), int64(concurrency),
		"handler must have seen at least `concurrency` requests for the overlap barrier to have engaged")

	conns := accepted.Load()
	t.Logf("%d requests over %d connections (%.1f requests/connection)",
		requests, conns, float64(requests)/float64(conns))

	// `concurrency` connections are genuinely required by the barrier above.
	// Anything much beyond that is the pool discarding connections instead of
	// reusing them; the regression lands near one connection per request.
	require.LessOrEqual(t, conns, int64(concurrency*2),
		"connections should be bounded by concurrency, not by request count")
}

// TestIdleConnPoolSize covers the sizing rule itself: a floor that -c raises
// when it is larger, payload threads raising it too, and nothing either of them
// declares shrinking it.
func TestIdleConnPoolSize(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		templateThreads int
		requestThreads  int
		want            int
	}{
		{name: "unset", templateThreads: 0, requestThreads: 0, want: defaultIdleConnPoolSize},
		{name: "default -c", templateThreads: 25, requestThreads: 0, want: defaultIdleConnPoolSize},
		{name: "-c 50", templateThreads: 50, requestThreads: 0, want: defaultIdleConnPoolSize},
		{name: "-c 800", templateThreads: 800, requestThreads: 0, want: 800},
		{name: "payload threads raise the pool", templateThreads: 25, requestThreads: 900, want: 900},
		{name: "payload threads never shrink the pool", templateThreads: 25, requestThreads: 2, want: defaultIdleConnPoolSize},
		{name: "payload threads never shrink -c 800", templateThreads: 800, requestThreads: 2, want: 800},
		{name: "negative payload threads never shrink the pool", templateThreads: 50, requestThreads: -1, want: defaultIdleConnPoolSize},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := idleConnPoolSize(testCase.templateThreads, testCase.requestThreads)
			require.Equal(t, testCase.want, got)
			require.GreaterOrEqual(t, got, defaultIdleConnPoolSize,
				"the floor exists because -c does not bound how many connections the transport opens")
			require.GreaterOrEqual(t, got, testCase.templateThreads,
				"the pool must never be smaller than the template concurrency it serves")
		})
	}
}

// TestIdleConnPoolSizeIsWiredToTransport checks that the size actually reaches
// the transport, not just the helper: a sizing rule that never lands on
// http.Transport would leave the reuse bug in place while the unit test above
// still passed.
func TestIdleConnPoolSizeIsWiredToTransport(t *testing.T) {
	opts := newTestOptions(t, "test-idle-conn-pool-wiring")
	opts.TemplateThreads = 800

	client, err := Get(opts, &Configuration{}, "example.com")
	require.NoError(t, err)

	tracking, ok := client.HTTPClient.Transport.(*connTrackingTransport)
	require.True(t, ok, "expected the connection-tracking transport wrapper")
	transport, ok := tracking.base.(*http.Transport)
	require.True(t, ok, "expected an *http.Transport underneath")

	require.Equal(t, 800, transport.MaxIdleConnsPerHost)
	require.Equal(t, 800, transport.MaxIdleConns)
}

// cyclicBarrier releases waiters in groups of n. A single-shot barrier only
// forces the FIRST group of requests to overlap, and a pool that is too small
// still looks fine afterwards, because once the requests stop overlapping a
// shallow pool is enough. Holding every group keeps the concurrency up for the
// whole run, which is what a scan does to a host.
type cyclicBarrier struct {
	mu        sync.Mutex
	n         int
	count     int
	gate      chan struct{}
	abandoned bool
}

func newCyclicBarrier(n int) *cyclicBarrier {
	return &cyclicBarrier{n: n, gate: make(chan struct{})}
}

func (b *cyclicBarrier) wait() {
	b.mu.Lock()
	if b.abandoned {
		b.mu.Unlock()
		return
	}
	b.count++
	gate := b.gate
	if b.count == b.n {
		b.count = 0
		b.gate = make(chan struct{})
		close(gate)
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	<-gate
}

// abandon is the safety valve: it stops blocking so a shortfall fails on the
// assertions instead of hanging the suite.
func (b *cyclicBarrier) abandon() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.abandoned {
		return
	}
	b.abandoned = true
	close(b.gate)
}

func (b *cyclicBarrier) wasAbandoned() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.abandoned
}

// TestIdleConnPoolAllowsKeepAliveReuseWithPayloadThreads covers the client that
// payload templates share. Configuration.Threads is part of the client cache
// key, so every template declaring the same payload thread count hashes to one
// entry and its workers pile onto a single pool -- templateThreads templates
// times payloadThreads workers each. That client has to reuse connections just
// like the default one, and a rule that sized the pool from a single template's
// threads would leave it far below the concurrency it actually serves.
func TestIdleConnPoolAllowsKeepAliveReuseWithPayloadThreads(t *testing.T) {
	const (
		templateThreads   = 10
		payloadThreads    = 5
		concurrency       = templateThreads * payloadThreads
		requestsPerWorker = 8
		requests          = concurrency * requestsPerWorker
	)

	var accepted atomic.Int64
	barrier := newCyclicBarrier(concurrency)
	timer := time.AfterFunc(30*time.Second, barrier.abandon)
	defer timer.Stop()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		barrier.wait()
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	opts := newTestOptions(t, "test-idle-conn-pool-payload-threads")
	opts.TemplateThreads = templateThreads

	// One client, as the engine would hand out: every payload template with
	// this thread count hashes to the same cache entry.
	client, err := Get(opts, &Configuration{Threads: payloadThreads}, server.Listener.Addr().String())
	require.NoError(t, err)

	var succeeded atomic.Int64
	var errMu sync.Mutex
	var firstErr error
	recordErr := func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}

	// templateThreads templates in flight, each running payloadThreads workers.
	var wg sync.WaitGroup
	for template := 0; template < templateThreads; template++ {
		for worker := 0; worker < payloadThreads; worker++ {
			wg.Add(1)
			go func(template, worker int) {
				defer wg.Done()

				for i := 0; i < requestsPerWorker; i++ {
					req, err := retryablehttp.NewRequest(http.MethodGet,
						fmt.Sprintf("%s/t-%d/w-%d/%d", server.URL, template, worker, i), nil)
					if err != nil {
						recordErr(err)
						barrier.abandon()
						return
					}
					resp, err := client.Do(req)
					if err != nil {
						recordErr(err)
						barrier.abandon()
						return
					}
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						_ = resp.Body.Close()
						recordErr(err)
						return
					}
					if err := resp.Body.Close(); err != nil {
						recordErr(err)
						return
					}
					succeeded.Add(1)
				}
			}(template, worker)
		}
	}
	wg.Wait()

	// Without these the connection assertion is vacuous: zero successful
	// requests also means zero connections.
	require.NoError(t, firstErr, "requests must succeed for the connection count to mean anything")
	require.Equal(t, int64(requests), succeeded.Load(), "all requests must succeed")
	require.False(t, barrier.wasAbandoned(),
		"the barrier must have held every group; the safety valve firing means the overlap was not sustained")

	conns := accepted.Load()
	t.Logf("%d requests over %d connections (%.1f requests/connection), pool=%d",
		requests, conns, float64(requests)/float64(conns),
		idleConnPoolSize(templateThreads, payloadThreads))

	require.LessOrEqual(t, conns, int64(concurrency*2),
		"connections should be bounded by the concurrency, not by the request count")
}
