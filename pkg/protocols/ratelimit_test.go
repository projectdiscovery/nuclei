package protocols_test

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostratelimit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestRateLimitTakePerHost(t *testing.T) {
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = 1
	options.RateLimitDuration = 300 * time.Millisecond
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	// the runner makes the global limiter unlimited in per-host mode
	global := utils.GetRateLimiter(context.Background(), 0, 0)
	t.Cleanup(global.Stop)
	executor := &protocols.ExecutorOptions{Options: options, RateLimiter: global}

	start := time.Now()
	for range 3 {
		require.NoError(t, executor.RateLimitTake("127.0.0.1:8000"))
	}
	require.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond, "one host must be limited")

	start = time.Now()
	for _, host := range []string{"127.0.0.1:8001", "127.0.0.1:8002", "example.com", "http://example.org/path"} {
		require.NoError(t, executor.RateLimitTake(host))
	}
	require.Less(t, time.Since(start), 250*time.Millisecond, "different hosts must not share a limiter")
}

func TestRateLimitTakeContextCancelsPerHostWait(t *testing.T) {
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.PerHostRateLimit = true
	options.RateLimit = 1
	options.RateLimitDuration = time.Second
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	global := utils.GetRateLimiter(context.Background(), 0, 0)
	t.Cleanup(global.Stop)
	executor := &protocols.ExecutorOptions{Options: options, RateLimiter: global}
	require.NoError(t, executor.RateLimitTakeContext(context.Background(), "cancel.example:443"))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- executor.RateLimitTakeContext(ctx, "cancel.example:443")
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	require.ErrorIs(t, <-result, context.Canceled)
}

func TestRateLimitTakeContextCancelsGlobalWait(t *testing.T) {
	global := utils.GetRateLimiter(context.Background(), 1, time.Hour)
	t.Cleanup(global.Stop)
	executor := &protocols.ExecutorOptions{RateLimiter: global}
	require.NoError(t, executor.RateLimitTakeContext(context.Background(), ""))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- executor.RateLimitTakeContext(ctx, "") }()
	select {
	case err := <-result:
		t.Fatalf("RateLimitTakeContext returned before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
}

func TestHostRateLimitKey(t *testing.T) {
	require.Equal(t, "example.com:8080", protocols.HostRateLimitKey("http://EXAMPLE.COM:8080/path"))
	require.Equal(t, "example.com:8080", protocols.HostRateLimitKey("example.com:8080"))
	require.Equal(t, "example.com:443", protocols.HostRateLimitKey("https://Example.com/a"))
	require.Equal(t, "example.com:80", protocols.HostRateLimitKey("http://example.com"))
}

func TestRateLimitTakeHostRateLimiterTakesPriority(t *testing.T) {
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())

	// a global limiter that would block for a long time must not be consulted
	global := utils.GetRateLimiter(context.Background(), 1, time.Hour)
	t.Cleanup(global.Stop)
	pool := hostratelimit.NewPool(context.Background(), hostratelimit.Options{MaxCount: 1, Duration: 300 * time.Millisecond})
	t.Cleanup(pool.Stop)
	executor := &protocols.ExecutorOptions{Options: options, RateLimiter: global, HostRateLimiter: pool}

	start := time.Now()
	for range 3 {
		require.NoError(t, executor.RateLimitTake("https://example.com/path"))
	}
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 500*time.Millisecond, "one host must be limited")
	require.Less(t, elapsed, 5*time.Second, "the global limiter must not be consulted")
	require.Equal(t, 1, pool.Len())

	// a redirect to the same origin shares the bucket of the original request
	require.NoError(t, executor.RateLimitTake("example.com:443"))
	require.Equal(t, 1, pool.Len())
}
