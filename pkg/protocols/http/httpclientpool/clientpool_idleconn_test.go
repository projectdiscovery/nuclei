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
