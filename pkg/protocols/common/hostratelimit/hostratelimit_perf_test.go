package hostratelimit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

// startTimingServer returns a server whose handler simply records every hit.
// The returned counter is goroutine-safe so callers can assert per-host
// dispatch rates.
func startTimingServer(t testing.TB) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func hostFromURL(t testing.TB, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Host
}

func drainGet(t testing.TB, client *http.Client, u string) {
	t.Helper()
	resp, err := client.Get(u)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestIntegration_PerHostBudgetIsEnforced verifies that, when M concurrent
// goroutines per host hammer the same target at full speed, the per-host
// limiter keeps each host's observed request rate within its configured
// budget. This is the end-to-end correctness check for the feature: the
// pool is wired in front of an actual HTTP client and we assert by counting
// server-side hits over a fixed window.
//
// Bounds are derived from the actual elapsed wall-clock so the test stays
// stable under scheduler jitter, with a generous +/-30% slack around the
// budgeted rate.
func TestIntegration_PerHostBudgetIsEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test uses real time-based budgets")
	}

	const (
		numHosts   = 4
		workersPer = 8
		budget     = 5 // tokens per duration per host
		duration   = 100 * time.Millisecond
		runFor     = 600 * time.Millisecond
	)

	servers := make([]*httptest.Server, numHosts)
	hits := make([]*atomic.Int64, numHosts)
	for i := 0; i < numHosts; i++ {
		servers[i], hits[i] = startTimingServer(t)
	}

	pool := NewPool(context.Background(), Options{
		MaxCount: budget,
		Duration: duration,
	})
	defer pool.Stop()

	client := &http.Client{Timeout: 5 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), runFor)
	defer cancel()

	var wg sync.WaitGroup
	start := time.Now()
	for _, srv := range servers {
		host := hostFromURL(t, srv.URL)
		for w := 0; w < workersPer; w++ {
			wg.Add(1)
			go func(host, url string) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					pool.Take(host)
					select {
					case <-ctx.Done():
						return
					default:
					}
					drainGet(t, client, url)
				}
			}(host, srv.URL)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	budgetedRate := float64(budget) / duration.Seconds() // req/sec per host
	const slack = 0.30
	for i := 0; i < numHosts; i++ {
		got := hits[i].Load()
		observedRate := float64(got) / elapsed.Seconds()
		t.Logf("host %d hits=%d (%.1f rps; budgeted %.1f rps)",
			i, got, observedRate, budgetedRate)

		require.LessOrEqualf(t, observedRate, budgetedRate*(1+slack),
			"host %d over budget: %.1f rps > %.1f rps (budget+slack)",
			i, observedRate, budgetedRate*(1+slack))
		require.GreaterOrEqualf(t, observedRate, budgetedRate*(1-slack),
			"host %d under-served (workers idle?): %.1f rps < %.1f rps (budget-slack)",
			i, observedRate, budgetedRate*(1-slack))
	}
	t.Logf("ran for %v across %d hosts × %d workers (budget %d / %v per host = %.0f rps each)",
		elapsed.Round(time.Millisecond), numHosts, workersPer, budget, duration, budgetedRate)
}

// TestPerformance_PerHostUnlocksParallelism is the speedup test.
//
// Both scenarios target the same effective per-host rate B tokens / D and run
// the same workload (numHosts * reqsPerHost). The difference is where the
// budget lives:
//
//	"global-only": one shared limiter at B/D; goroutines for every host
//	               serialize through the same bucket. Wall-clock floor:
//	               numHosts * reqsPerHost / (B/D).
//	"per-host":    one limiter per host at B/D; goroutines for different
//	               hosts run in parallel up to numHosts × B/D total.
//	               Wall-clock floor: reqsPerHost / (B/D).
//
// Workload is sized so the global-only run requires several refill windows
// (otherwise both schemes finish under one tick and the test measures noise
// instead of the rate-limiter behavior). Speedup ≈ numHosts. We assert it's
// at least numHosts/2 to keep the test stable on busy CI without losing
// the signal. Wall-clock numbers are always logged for visibility.
func TestPerformance_PerHostUnlocksParallelism(t *testing.T) {
	if testing.Short() {
		t.Skip("speedup test uses real time-based budgets")
	}

	const (
		numHosts    = 8
		reqsPerHost = 20
		budget      = 10 // tokens (= 100 rps per limiter at duration=100ms)
		duration    = 100 * time.Millisecond
	)

	runGlobalOnly := func(t *testing.T) time.Duration {
		global := ratelimit.New(context.Background(), budget, duration)
		defer global.Stop()
		var wg sync.WaitGroup
		start := time.Now()
		for h := 0; h < numHosts; h++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := 0; r < reqsPerHost; r++ {
					global.Take()
				}
			}()
		}
		wg.Wait()
		return time.Since(start)
	}

	runPerHost := func(t *testing.T) time.Duration {
		pool := NewPool(context.Background(), Options{
			MaxCount: budget,
			Duration: duration,
		})
		defer pool.Stop()
		var wg sync.WaitGroup
		start := time.Now()
		for h := 0; h < numHosts; h++ {
			host := fmt.Sprintf("h-%d", h)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := 0; r < reqsPerHost; r++ {
					pool.Take(host)
				}
			}()
		}
		wg.Wait()
		return time.Since(start)
	}

	// Warm both schemes once to make sure goroutines and timers are
	// scheduled before measurement.
	_ = runGlobalOnly(t)
	_ = runPerHost(t)

	const repeats = 3
	var globalSum, perHostSum time.Duration
	for i := 0; i < repeats; i++ {
		globalSum += runGlobalOnly(t)
		perHostSum += runPerHost(t)
	}
	globalAvg := globalSum / repeats
	perHostAvg := perHostSum / repeats

	speedup := float64(globalAvg) / float64(perHostAvg)
	totalReqs := numHosts * reqsPerHost
	t.Logf("workload: %d hosts × %d reqs (= %d total) at budget %d/%v per host",
		numHosts, reqsPerHost, totalReqs, budget, duration)
	t.Logf("global-only average: %v  (%.0f rps)",
		globalAvg.Round(time.Millisecond),
		float64(totalReqs)/globalAvg.Seconds())
	t.Logf("per-host  average: %v  (%.0f rps)",
		perHostAvg.Round(time.Millisecond),
		float64(totalReqs)/perHostAvg.Seconds())
	t.Logf("speedup: %.2fx (theoretical ceiling = %d)", speedup, numHosts)

	// We expect at least half the theoretical N× speedup. Even on a busy
	// machine this gap is huge; if it shrinks below half it almost
	// certainly means the per-host pool is funneling through a single
	// limiter and the regression is worth investigating.
	require.GreaterOrEqual(t, speedup, float64(numHosts)/2,
		"per-host limiter failed to unlock host parallelism: speedup=%.2fx", speedup)
}

// We want to measure pure Take() code overhead, not the rate limiter's
// enforcement sleeps. ratelimit.Limiter starts with `max` tokens then
// refills at max/duration. To keep the bucket from ever depleting during
// the benchmark we size it well above b.N (Go benchmarks rarely go past
// 1e8 iterations even at -benchtime=10s).
const benchMaxCount = 1 << 30 // ~1.07B tokens, never depleted in-bench.

// BenchmarkPool_Take_HotHost measures Take() overhead in steady state when
// the limiter has plenty of tokens (no blocking on the bucket). This is the
// per-call cost we add to every request when per-host limiting is enabled.
func BenchmarkPool_Take_HotHost(b *testing.B) {
	p := NewPool(context.Background(), Options{
		MaxCount: benchMaxCount,
		Duration: time.Second,
	})
	defer p.Stop()
	const host = "hot.example.com"
	p.Take(host) // warm the entry

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Take(host)
	}
}

// BenchmarkPool_Take_ManyHosts measures the cost of cycling Take() across a
// large host set, exercising the map lookup + lastAccess update on the hot
// path. This is the realistic shape for template-spray scans where a worker
// hops between many targets.
func BenchmarkPool_Take_ManyHosts(b *testing.B) {
	const numHosts = 1024
	hosts := make([]string, numHosts)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h-%d.example.com", i)
	}

	p := NewPool(context.Background(), Options{
		MaxCount: benchMaxCount,
		Duration: time.Second,
		MaxHosts: numHosts * 2, // avoid LRU eviction during the benchmark
	})
	defer p.Stop()
	for _, h := range hosts {
		p.Take(h)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Take(hosts[i&(numHosts-1)])
	}
}

// BenchmarkPool_Take_NilPool measures the cost of Take() on a nil *Pool, the
// path taken when per-host limiting is disabled. This must be effectively
// free so we can leave RateLimitTakeFor in the hot path unconditionally.
func BenchmarkPool_Take_NilPool(b *testing.B) {
	var p *Pool
	const host = "any.example.com"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Take(host)
	}
}

// BenchmarkPool_Take_Parallel models concurrent Take() across many hosts,
// the realistic SDK shape where worker pools hit the limiter from multiple
// goroutines simultaneously. With MaxCount well above the call rate the
// bucket never blocks; we're measuring lock contention on the pool map.
func BenchmarkPool_Take_Parallel(b *testing.B) {
	const numHosts = 256
	hosts := make([]string, numHosts)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h-%d.example.com", i)
	}
	p := NewPool(context.Background(), Options{
		MaxCount: benchMaxCount,
		Duration: time.Second,
		MaxHosts: numHosts * 2,
	})
	defer p.Stop()
	for _, h := range hosts {
		p.Take(h)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			p.Take(hosts[i&(numHosts-1)])
			i++
		}
	})
}
