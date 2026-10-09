package protocols_test

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
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
