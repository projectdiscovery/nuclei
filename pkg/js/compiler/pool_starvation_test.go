package compiler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	syncutil "github.com/projectdiscovery/utils/sync"
)

// TestPoolSlotStarvation reproduces the core bug from issue #6894:
// zombie goroutines from timed-out JS executions hold pool slots
// indefinitely, causing subsequent executions to fail.
//
// The flow:
//  1. ExecFuncWithTwoReturns wraps ExecuteProgram in a goroutine with a deadline.
//  2. Inside ExecuteProgram, pool.Add() acquires a slot, defer pool.Done() is set.
//  3. The JS script makes a network call using context.TODO() (no deadline).
//  4. The deadline fires and ExecFuncWithTwoReturns returns the deadline error.
//  5. The goroutine is STILL running (zombie), holding the pool slot via defer.
//  6. With enough zombies, all slots are consumed and new executions time out
//     waiting for a slot that will never be released.
func TestPoolSlotStarvation(t *testing.T) {
	const poolSize = 3
	pool, err := syncutil.New(syncutil.WithSize(poolSize))
	require.NoError(t, err)

	// Simulate zombies: goroutines that acquire a slot, then block for a
	// long time (as if stuck on a network call with context.TODO()).
	// The caller "abandons" them via a short deadline.
	var zombieWg sync.WaitGroup
	for i := range poolSize {
		zombieWg.Add(1)
		go func(idx int) {
			defer zombieWg.Done()
			// This is what happens inside executeWithoutPooling/executeWithPoolingProgram:
			pool.Add()
			defer pool.Done()
			// Simulate a stuck network call (15s in the original report).
			time.Sleep(10 * time.Second)
		}(i)
	}

	// Give zombies time to acquire their slots.
	time.Sleep(100 * time.Millisecond)

	// All slots are held by zombies. Try to acquire a new slot with a
	// deadline - this should fail because no slots are available and
	// zombies won't release them for ~10s.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = pool.AddWithContext(ctx)
	elapsed := time.Since(start)

	// This demonstrates the starvation: the pool is fully exhausted by zombies,
	// and the new acquisition times out.
	require.Error(t, err, "should fail, all slots held by zombie goroutines")
	require.Less(t, elapsed, 2*time.Second, "should fail fast at deadline, not block forever")
	t.Logf("Pool starvation confirmed: new slot acquisition failed after %v (pool exhausted by %d zombies)", elapsed, poolSize)
}

// TestWatchdogPreventsStarvation demonstrates the fix: a watchdog goroutine
// releases pool slots when the deadline expires, even if the zombie is still
// running. This is the core of the fix in PR #6896.
func TestWatchdogPreventsStarvation(t *testing.T) {
	const poolSize = 3
	pool, err := syncutil.New(syncutil.WithSize(poolSize))
	require.NoError(t, err)

	// Fill all slots with "zombies" that have a 100ms deadline but block for
	// 10s. The watchdog pattern releases each slot when the deadline fires.
	for i := range poolSize {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		require.NoError(t, pool.AddWithContext(ctx), "initial acquisition %d", i)

		watchdogDone := make(chan struct{})
		var once sync.Once

		releaseSlot := func() {
			once.Do(func() { pool.Done() })
		}

		// Watchdog: free the slot when deadline expires.
		go func() {
			select {
			case <-ctx.Done():
				releaseSlot()
			case <-watchdogDone:
			}
		}()

		// Zombie worker: blocks for 10s but the watchdog will free its slot.
		go func() {
			defer func() {
				close(watchdogDone)
				releaseSlot()
			}()
			time.Sleep(10 * time.Second)
		}()
	}

	// Wait for all deadlines to fire and watchdogs to release slots.
	time.Sleep(200 * time.Millisecond)

	// All slots should be free now, so new acquisitions should work.
	for i := range poolSize {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		require.NoError(t, pool.AddWithContext(ctx),
			"post-recovery acquisition %d/%d (pool should no longer be starved)", i+1, poolSize)
		pool.Done()
	}

	t.Log("Watchdog fix confirmed: all slots recovered after zombie deadline expiry")
}
