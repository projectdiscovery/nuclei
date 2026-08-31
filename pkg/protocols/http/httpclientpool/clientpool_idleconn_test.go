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
// The server here counts accepted connections, which is what actually matters:
// connection churn is invisible in request counts but is what exhausts NAT
// port mappings and pays a TCP (and TLS) handshake per request.
func TestIdleConnPoolAllowsKeepAliveReuse(t *testing.T) {
	const (
		requests    = 400
		concurrency = 50
	)

	var accepted atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			req, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/path-%d", server.URL, i), nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			// Drain and close so the connection is eligible for reuse.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	wg.Wait()

	conns := accepted.Load()
	t.Logf("%d requests over %d connections (%.1f requests/connection)",
		requests, conns, float64(requests)/float64(conns))

	// Steady state needs at most `concurrency` connections in flight. Allow
	// generous headroom for scheduling jitter while still failing loudly on
	// the ~1-connection-per-request regression, which would land near 400.
	require.LessOrEqual(t, conns, int64(concurrency*2),
		"connections should be bounded by concurrency, not by request count")
}
