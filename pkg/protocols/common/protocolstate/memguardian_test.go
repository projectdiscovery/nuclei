package protocolstate

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/memguardian"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

// TestMemGuardianGoroutineLeak tests that MemGuardian properly cleans up goroutines
func TestMemGuardianGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreAnyContainingPkg("go.opencensus.io/stats/view"),
		goleak.IgnoreAnyContainingPkg("github.com/syndtr/goleveldb"),
		goleak.IgnoreAnyContainingPkg("github.com/go-rod/rod"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/interactsh/pkg/server"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/ratelimit"),
	)

	// Initialize memguardian if not already initialized
	if memguardian.DefaultMemGuardian == nil {
		var err error
		memguardian.DefaultMemGuardian, err = memguardian.New()
		require.NoError(t, err, "Failed to initialize memguardian")
	}

	t.Run("StartAndStopMemGuardian", func(t *testing.T) {
		// Test that starting and stopping memguardian doesn't leak goroutines
		ctx := context.Background()

		// Start MemGuardian
		StartActiveMemGuardian(ctx)
		require.NotNil(t, memTimer, "memTimer should be initialized")
		require.NotNil(t, cancelFunc, "cancelFunc should be initialized")

		// Give it a moment to start
		time.Sleep(10 * time.Millisecond)

		// Stop MemGuardian
		StopActiveMemGuardian()

		// Give goroutine time to exit
		time.Sleep(20 * time.Millisecond)

		// Verify cleanup
		require.Nil(t, memTimer, "memTimer should be nil after stop")
		require.Nil(t, cancelFunc, "cancelFunc should be nil after stop")
	})

	t.Run("MultipleStartStop", func(t *testing.T) {
		// Test multiple start/stop cycles
		for i := 0; i < 3; i++ {
			ctx := context.Background()
			StartActiveMemGuardian(ctx)
			time.Sleep(5 * time.Millisecond)
			StopActiveMemGuardian()
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		// Test that context cancellation properly stops the goroutine
		ctx, cancel := context.WithCancel(context.Background())

		StartActiveMemGuardian(ctx)
		require.NotNil(t, memTimer, "memTimer should be initialized")

		// Cancel context to trigger goroutine exit
		cancel()

		// Give it time to process cancellation
		time.Sleep(20 * time.Millisecond)

		// Clean up
		StopActiveMemGuardian()
		time.Sleep(10 * time.Millisecond)
	})

	t.Run("IdempotentStart", func(t *testing.T) {
		// Test that multiple starts don't create multiple goroutines
		ctx := context.Background()

		StartActiveMemGuardian(ctx)
		firstTimer := memTimer

		// Start again - should be idempotent
		StartActiveMemGuardian(ctx)
		require.Equal(t, firstTimer, memTimer, "memTimer should be the same")
		require.NotNil(t, cancelFunc, "cancelFunc should still be set")

		StopActiveMemGuardian()
		time.Sleep(10 * time.Millisecond)
	})
}

// TestMemGuardianReset tests resetting global state
func TestMemGuardianReset(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreAnyContainingPkg("go.opencensus.io/stats/view"),
		goleak.IgnoreAnyContainingPkg("github.com/syndtr/goleveldb"),
		goleak.IgnoreAnyContainingPkg("github.com/go-rod/rod"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/interactsh/pkg/server"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/ratelimit"),
	)

	// Ensure clean state
	StopActiveMemGuardian()
	time.Sleep(20 * time.Millisecond) // Allow any existing goroutines to exit

	// Test that we can start after stop
	ctx := context.Background()
	StartActiveMemGuardian(ctx)

	// Verify it started
	require.NotNil(t, memTimer, "memTimer should be initialized after restart")

	// Clean up
	StopActiveMemGuardian()
	time.Sleep(10 * time.Millisecond) // Allow cleanup
}
