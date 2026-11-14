package protocols_test

import (
	"context"
	"fmt"
	"runtime"
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

// hostRateLimitExecutor returns an executor with -rate-limit-host set to limit
// requests per duration, and a global limiter that would block for an hour.
func hostRateLimitExecutor(t *testing.T, limit int, duration time.Duration) *protocols.ExecutorOptions {
	t.Helper()
	options := types.DefaultOptions()
	options.SetExecutionID(t.Name())
	options.RateLimit = 1
	options.RateLimitDuration = time.Hour
	options.RateLimitHost = limit
	options.RateLimitHostDuration = duration
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	global := utils.GetRateLimiter(context.Background(), options.RateLimit, options.RateLimitDuration)
	t.Cleanup(global.Stop)
	// spend the only global token, so any use of the global limiter blocks
	require.NoError(t, global.TakeContext(context.Background()))
	return &protocols.ExecutorOptions{Options: options, RateLimiter: global}
}

func perHostPoolSize(t *testing.T, options *types.Options) int {
	t.Helper()
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	require.NotNil(t, dialers)
	dialers.Lock()
	defer dialers.Unlock()
	pool, ok := dialers.PerHostRateLimitPool.(*hostratelimit.PerHostRateLimitPool)
	require.True(t, ok)
	return pool.Size()
}

func TestRateLimitTakeHostRateLimitTakesPriority(t *testing.T) {
	executor := hostRateLimitExecutor(t, 1, 300*time.Millisecond)

	start := time.Now()
	for range 3 {
		require.NoError(t, executor.RateLimitTake("https://example.com/path"))
	}
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 500*time.Millisecond, "one host must be limited")
	require.Less(t, elapsed, 5*time.Second, "the global limiter must not be consulted")
	require.Equal(t, 1, perHostPoolSize(t, executor.Options))

	// a redirect to the same origin shares the bucket of the original request
	require.NoError(t, executor.RateLimitTake("EXAMPLE.com:443"))
	require.Equal(t, 1, perHostPoolSize(t, executor.Options))

	// other hosts have their own budget
	start = time.Now()
	for _, host := range []string{"127.0.0.1:8001", "127.0.0.1:8002", "http://example.org/path"} {
		require.NoError(t, executor.RateLimitTake(host))
	}
	require.Less(t, time.Since(start), 250*time.Millisecond, "different hosts must not share a limiter")
}

func TestRateLimitTakeHostRateLimitCancelKeepsToken(t *testing.T) {
	executor := hostRateLimitExecutor(t, 1, time.Second)
	host := "https://cancel.example"

	start := time.Now()
	require.NoError(t, executor.RateLimitTakeContext(context.Background(), host))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- executor.RateLimitTakeContext(ctx, host) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("a canceled wait must return at once")
	}

	// the canceled wait gave its token back: the next request is admitted one
	// interval after the first, not two
	require.NoError(t, executor.RateLimitTakeContext(context.Background(), host))
	require.Less(t, time.Since(start), 1700*time.Millisecond)
}

func TestRateLimitTakeHostRateLimitStartsNoGoroutines(t *testing.T) {
	executor := hostRateLimitExecutor(t, 5, time.Second)
	// the first call creates the pool
	require.NoError(t, executor.RateLimitTake("https://warmup.example"))

	before := runtime.NumGoroutine()
	for i := range 200 {
		require.NoError(t, executor.RateLimitTake(fmt.Sprintf("https://host-%d.example", i)))
	}
	require.Equal(t, 201, perHostPoolSize(t, executor.Options))
	require.Less(t, runtime.NumGoroutine()-before, 10, "per-host limiters must not start goroutines")
}
