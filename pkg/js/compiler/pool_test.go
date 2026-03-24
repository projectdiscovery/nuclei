package compiler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	syncutil "github.com/projectdiscovery/utils/sync"
)

// TestAddWithContextRespectsDeadline verifies that AddWithContext returns an
// error when the context deadline expires while waiting for a pool slot.
// Before the fix, Add() used context.Background() and would block indefinitely.
func TestAddWithContextRespectsDeadline(t *testing.T) {
	pool, err := syncutil.New(syncutil.WithSize(1))
	require.NoError(t, err)

	// Fill the only slot.
	pool.Add()
	defer pool.Done()

	// Try to acquire with a short deadline, should fail fast and not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = pool.AddWithContext(ctx)
	elapsed := time.Since(start)

	require.Error(t, err, "AddWithContext should fail when pool is full and deadline expires")
	require.Less(t, elapsed, 200*time.Millisecond, "AddWithContext should fail fast after deadline")
}

// TestWatchdogReleasesSlotOnDeadline verifies that the watchdog goroutine
// releases a pool slot when the execution deadline expires, even if the
// worker goroutine is still running (zombie). This is the core fix for
// pool slot starvation: without the watchdog, a zombie goroutine holds its
// slot via defer Done() until its network call eventually times out (or never).
func TestWatchdogReleasesSlotOnDeadline(t *testing.T) {
	pool, err := syncutil.New(syncutil.WithSize(1))
	require.NoError(t, err)

	// Acquire the only slot (simulates a JS execution starting).
	pool.Add()

	// Set up the watchdog pattern (same as our fix in pool.go / non-pool.go).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var slotReleased atomic.Bool
	watchdogDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if slotReleased.CompareAndSwap(false, true) {
				pool.Done()
			}
		case <-watchdogDone:
		}
	}()
	defer func() {
		close(watchdogDone)
		if slotReleased.CompareAndSwap(false, true) {
			pool.Done()
		}
	}()

	// Wait for the deadline to fire and the watchdog to release the slot.
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	// A new execution should be able to acquire the slot, even though the
	// "zombie" never called Done() itself.
	freshCtx, freshCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer freshCancel()
	require.NoError(t, pool.AddWithContext(freshCtx),
		"slot acquisition should succeed after watchdog release")
	pool.Done()
}

// TestPoolExhaustionRecovery demonstrates the complete starvation/recovery
// cycle. All pool slots are filled with zombie goroutines that block well
// beyond their deadline. The watchdog pattern frees the slots when the
// deadlines expire, allowing subsequent executions to proceed.
//
// Without the fix, the pool stays permanently exhausted and every subsequent
// AddWithContext call fails (or Add() blocks forever).
func TestPoolExhaustionRecovery(t *testing.T) {
	const poolSize = 3
	pool, err := syncutil.New(syncutil.WithSize(poolSize))
	require.NoError(t, err)

	// Fill every slot with a "zombie" that blocks for 10s but has a 100ms
	// deadline. The watchdog should free each slot after ~100ms.
	for i := range poolSize {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		require.NoError(t, pool.AddWithContext(ctx), "initial slot acquisition %d", i)

		var released atomic.Bool
		done := make(chan struct{})

		// Watchdog: release slot when deadline expires.
		go func() {
			select {
			case <-ctx.Done():
				if released.CompareAndSwap(false, true) {
					pool.Done()
				}
			case <-done:
			}
		}()

		// Zombie worker: blocks for 10s simulating a hung network call.
		go func() {
			defer func() {
				close(done)
				if released.CompareAndSwap(false, true) {
					pool.Done()
				}
			}()
			time.Sleep(10 * time.Second)
		}()
	}

	// Pool is fully saturated. Wait for all deadlines to expire.
	time.Sleep(200 * time.Millisecond)

	// All slots should now be free. Acquire and release each one.
	for i := range poolSize {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		require.NoError(t, pool.AddWithContext(ctx),
			"post-recovery slot acquisition %d/%d (pool still starved)", i+1, poolSize)
		pool.Done()
	}
}
