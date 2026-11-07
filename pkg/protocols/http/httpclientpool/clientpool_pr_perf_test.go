package httpclientpool

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Benchmarks measuring the end-to-end effect of per-host pooling delivered by
// this PR. Two scenarios are compared on the same workload of N hosts × M
// requests per host:
//
//   * "before": a single shared client with keep-alive disabled, mirroring
//     pre-PR behavior on a host-spray strategy where every request opened a
//     fresh connection.
//
//   * "after":  one client per host obtained from httpclientpool.Get(...,
//     hostname). Keep-alive is always enabled and idle connections are
//     reused by the per-host transport pool.
//
// Numbers are most striking for HTTPS, where avoiding the TLS handshake on
// every request dominates the runtime.

const (
	prBenchHosts        = 10
	prBenchRequestsHost = 20
)

func setupPRBenchOptions(b *testing.B, executionId string) *types.Options {
	b.Helper()
	opts := types.DefaultOptions()
	opts.SetExecutionID(executionId)
	require.NoError(b, protocolstate.Init(opts))
	b.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	return opts
}

func startPRTLSServers(b *testing.B, n int) []*httptest.Server {
	b.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})
	servers := make([]*httptest.Server, n)
	for i := range servers {
		servers[i] = httptest.NewTLSServer(handler)
	}
	b.Cleanup(func() {
		for _, s := range servers {
			s.Close()
		}
	})
	return servers
}

func startPRHTTPServers(b *testing.B, n int) []*httptest.Server {
	b.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})
	servers := make([]*httptest.Server, n)
	for i := range servers {
		servers[i] = httptest.NewServer(handler)
	}
	b.Cleanup(func() {
		for _, s := range servers {
			s.Close()
		}
	})
	return servers
}

// hostFromURL extracts host:port from an httptest.Server.URL.
func hostFromURL(b *testing.B, raw string) string {
	b.Helper()
	u, err := url.Parse(raw)
	require.NoError(b, err)
	return u.Host
}

// sharedClientNoKeepAlive mirrors the pre-PR shared-client + keep-alive-OFF
// path, which forced a brand new connection (and a TLS handshake when
// applicable) on every request.
func sharedClientNoKeepAlive() *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// runBeforePR drives the workload with a single shared client and keep-alive
// disabled.
func runBeforePR(b *testing.B, servers []*httptest.Server) {
	b.Helper()
	client := sharedClientNoKeepAlive()
	for _, srv := range servers {
		for i := 0; i < prBenchRequestsHost; i++ {
			resp, err := client.Get(srv.URL + fmt.Sprintf("/r%d", i))
			require.NoError(b, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
}

// runAfterPR drives the same workload using httpclientpool.Get(... host) so
// each host gets its own keep-alive enabled client, matching the path taken
// by request.go after this PR.
func runAfterPR(b *testing.B, opts *types.Options, servers []*httptest.Server) {
	b.Helper()
	cfg := &Configuration{}
	for _, srv := range servers {
		host := hostFromURL(b, srv.URL)
		client, err := Get(opts, cfg, host)
		require.NoError(b, err)
		for i := 0; i < prBenchRequestsHost; i++ {
			req, err := http.NewRequest(http.MethodGet, srv.URL+fmt.Sprintf("/r%d", i), nil)
			require.NoError(b, err)
			resp, err := client.HTTPClient.Do(req)
			require.NoError(b, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
}

// runAfterPRConcurrent drives the workload with one goroutine per host so
// the per-host pool benefit is measured under realistic scan concurrency.
func runAfterPRConcurrent(b *testing.B, opts *types.Options, servers []*httptest.Server) {
	b.Helper()
	cfg := &Configuration{}
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *httptest.Server) {
			defer wg.Done()
			host := hostFromURL(b, s.URL)
			client, err := Get(opts, cfg, host)
			if err != nil {
				b.Errorf("Get(%s): %v", host, err)
				return
			}
			for i := 0; i < prBenchRequestsHost; i++ {
				req, err := http.NewRequest(http.MethodGet, s.URL+fmt.Sprintf("/r%d", i), nil)
				if err != nil {
					b.Errorf("new request: %v", err)
					return
				}
				resp, err := client.HTTPClient.Do(req)
				if err != nil {
					b.Errorf("do: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(srv)
	}
	wg.Wait()
}

// HTTPS — TLS handshake amplifies the win.

func BenchmarkPR_BeforePR_HTTPS(b *testing.B) {
	servers := startPRTLSServers(b, prBenchHosts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runBeforePR(b, servers)
	}
}

func BenchmarkPR_AfterPR_HTTPS(b *testing.B) {
	opts := setupPRBenchOptions(b, "bench-after-pr-https")
	servers := startPRTLSServers(b, prBenchHosts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runAfterPR(b, opts, servers)
	}
}

func BenchmarkPR_AfterPR_HTTPS_Concurrent(b *testing.B) {
	opts := setupPRBenchOptions(b, "bench-after-pr-https-concurrent")
	servers := startPRTLSServers(b, prBenchHosts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runAfterPRConcurrent(b, opts, servers)
	}
}

// HTTP — keep-alive still wins because it skips TCP setup on every request.

func BenchmarkPR_BeforePR_HTTP(b *testing.B) {
	servers := startPRHTTPServers(b, prBenchHosts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runBeforePR(b, servers)
	}
}

func BenchmarkPR_AfterPR_HTTP(b *testing.B) {
	opts := setupPRBenchOptions(b, "bench-after-pr-http")
	servers := startPRHTTPServers(b, prBenchHosts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runAfterPR(b, opts, servers)
	}
}
