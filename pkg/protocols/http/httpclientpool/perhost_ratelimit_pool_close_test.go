package httpclientpool

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestPerHostRateLimitPool_CloseReleasesLimiters ensures Close() drains the pool
// and releases the per-host rate limiter goroutines (one per host) instead of
// leaking them. protocolstate.Close wires this in so a long-running embedder
// that recreates engines does not accumulate limiter goroutines over time.
func TestPerHostRateLimitPool_CloseReleasesLimiters(t *testing.T) {
	opts := &types.Options{RateLimit: 100, RateLimitDuration: time.Second}
	pool := NewPerHostRateLimitPool(1024, time.Hour, time.Hour, opts)

	runtime.GC()
	base := runtime.NumGoroutine()

	const n = 50
	for i := 0; i < n; i++ {
		_, err := pool.GetOrCreate(fmt.Sprintf("http://host%d.example.com:443", i))
		require.NoError(t, err)
	}
	require.Equal(t, n, pool.Size())
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() > base
	}, time.Second, 20*time.Millisecond, "limiter goroutines should be running before Close")

	pool.Close()
	require.Equal(t, 0, pool.Size(), "Close must empty the pool")

	// cancelled limiter goroutines exit asynchronously
	require.Eventually(t, func() bool {
		runtime.GC()
		return runtime.NumGoroutine()-base <= n/5
	}, 3*time.Second, 20*time.Millisecond, "limiter goroutines should be released after Close")
}
