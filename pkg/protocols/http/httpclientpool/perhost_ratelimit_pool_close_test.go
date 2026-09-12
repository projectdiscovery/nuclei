package httpclientpool

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestPerHostRateLimitPoolDoesNotCreateGoroutinePerHost ensures a large target
// set does not create one fixed-window refill goroutine for every host.
func TestPerHostRateLimitPoolDoesNotCreateGoroutinePerHost(t *testing.T) {
	opts := &types.Options{RateLimit: 100, RateLimitDuration: time.Second}
	pool := NewPerHostRateLimitPool(1024, time.Hour, time.Hour, opts)

	runtime.GC()
	base := runtime.NumGoroutine()

	const n = 500
	for i := 0; i < n; i++ {
		_, err := pool.GetOrCreate(fmt.Sprintf("http://host%d.example.com:443", i))
		require.NoError(t, err)
	}
	require.Equal(t, n, pool.Size())
	runtime.Gosched()
	require.LessOrEqual(t, runtime.NumGoroutine()-base, 5,
		"host limiters must not create O(hosts) background goroutines")

	pool.Close()
	require.Equal(t, 0, pool.Size(), "Close must empty the pool")
}

func TestPerHostRateLimitPoolSmoothsLowRates(t *testing.T) {
	opts := &types.Options{RateLimit: 50, RateLimitDuration: time.Second}
	pool := NewPerHostRateLimitPool(1, time.Hour, time.Hour, opts)
	t.Cleanup(pool.Close)

	limiter, err := pool.GetOrCreate("https://smooth.example.com")
	require.NoError(t, err)
	started := time.Now()
	for range 51 {
		limiter.Take()
	}
	require.Less(t, time.Since(started), 500*time.Millisecond,
		"the first request beyond the initial bucket should be continuously refilled, not wait for a fixed window")
}

func TestUnboundedPerHostRateLimitPoolRetainsBudgetsBeyondDefaultCapacity(t *testing.T) {
	opts := &types.Options{RateLimit: 10, RateLimitDuration: time.Second}
	pool := NewPerHostRateLimitPool(0, time.Hour, time.Hour, opts)
	t.Cleanup(pool.Close)

	first, err := pool.GetOrCreate("https://first.example.com")
	require.NoError(t, err)
	for i := 0; i < 2048; i++ {
		_, err = pool.GetOrCreate(fmt.Sprintf("https://host%d.example.com", i))
		require.NoError(t, err)
	}
	again, err := pool.GetOrCreate("https://first.example.com")
	require.NoError(t, err)

	require.Same(t, first, again, "large scans must not receive a fresh host budget after table churn")
	require.Equal(t, 2049, pool.Size())
	require.Zero(t, pool.Stats().Evictions)
}
