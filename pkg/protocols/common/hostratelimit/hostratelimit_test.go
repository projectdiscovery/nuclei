package hostratelimit

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

// TestNewPool_DisabledReturnsNil verifies that an Options with MaxCount==0
// produces a nil pool, since callers rely on a nil *Pool being a valid no-op,
// while a non-positive Duration is normalized to DefaultDuration instead of
// disabling the pool.
func TestNewPool_DisabledReturnsNil(t *testing.T) {
	require.Nil(t, NewPool(context.Background(), Options{}))
	require.Nil(t, NewPool(context.Background(), Options{Duration: time.Second}))

	p := NewPool(context.Background(), Options{MaxCount: 10})
	require.NotNil(t, p, "zero duration must default to DefaultDuration, not disable")
	require.Equal(t, DefaultDuration, p.opts.Duration)
	p.Stop()

	p = NewPool(context.Background(), Options{MaxCount: 10, Duration: -time.Second})
	require.NotNil(t, p)
	require.Equal(t, DefaultDuration, p.opts.Duration, "negative duration must be normalized")
	p.Stop()
}

// TestPool_NilIsNoOp asserts that all public methods are safe on a nil pool,
// matching the comment on Pool that says callers can treat a nil pool as
// disabled.
func TestPool_NilIsNoOp(t *testing.T) {
	var p *Pool
	require.NotPanics(t, func() {
		p.Take("example.com")
		require.Nil(t, p.Get("example.com"))
		require.Equal(t, 0, p.Len())
		p.Stop()
	})
}

// TestPool_SameHostReusesLimiter verifies the per-host cache: the second Get
// for the same host must return the same *ratelimit.Limiter so requests
// against one host share a single token bucket.
func TestPool_SameHostReusesLimiter(t *testing.T) {
	p := NewPool(context.Background(), Options{MaxCount: 10, Duration: time.Second})
	defer p.Stop()

	l1 := p.Get("example.com")
	l2 := p.Get("example.com")
	require.Same(t, l1, l2, "same host must reuse the cached limiter")
	require.Equal(t, 1, p.Len())
}

// TestPool_DifferentHostsAreIsolated verifies that different hosts get
// distinct limiters, which is the whole point of per-host limiting.
func TestPool_DifferentHostsAreIsolated(t *testing.T) {
	p := NewPool(context.Background(), Options{MaxCount: 10, Duration: time.Second})
	defer p.Stop()

	l1 := p.Get("a.example.com")
	l2 := p.Get("b.example.com")
	require.NotNil(t, l1)
	require.NotNil(t, l2)
	require.NotSame(t, l1, l2, "different hosts must have different limiters")
	require.Equal(t, 2, p.Len())
}

// TestPool_EvictsIdleEntries verifies that the background sweep reclaims
// entries that have been inactive longer than Options.Inactivity, and that
// the evicted limiter is Stop()-ed (no goroutine leak).
func TestPool_EvictsIdleEntries(t *testing.T) {
	p := NewPool(context.Background(), Options{
		MaxCount:      10,
		Duration:      time.Second,
		Inactivity:    50 * time.Millisecond,
		SweepInterval: 25 * time.Millisecond,
	})
	defer p.Stop()

	_ = p.Get("a.example.com")
	require.Equal(t, 1, p.Len())

	require.Eventually(t, func() bool {
		return p.Len() == 0
	}, time.Second, 10*time.Millisecond, "idle entry should be evicted by the sweep")

	p.mu.Lock()
	stops := p.stoppedLimiters
	p.mu.Unlock()
	require.GreaterOrEqual(t, stops, uint64(1),
		"sweep must Stop() the evicted limiter to release its goroutine")
}

// TestPool_LRUCapEvictsOldest verifies the hard cap: when the pool is full,
// inserting a new host evicts the least-recently-used entry. This bounds
// worst-case memory on scans across very large input sets.
func TestPool_LRUCapEvictsOldest(t *testing.T) {
	p := NewPool(context.Background(), Options{
		MaxCount: 10,
		Duration: time.Second,
		MaxHosts: 2,
	})
	defer p.Stop()

	_ = p.Get("a")
	time.Sleep(2 * time.Millisecond)
	_ = p.Get("b")
	require.Equal(t, 2, p.Len())

	// Touching "a" makes "b" the LRU; inserting "c" must evict "b", not "a".
	time.Sleep(2 * time.Millisecond)
	_ = p.Get("a")
	time.Sleep(2 * time.Millisecond)
	_ = p.Get("c")

	require.Equal(t, 2, p.Len())
	require.NotNil(t, p.peek("a"), "most recently touched key must survive")
	require.NotNil(t, p.peek("c"), "newly inserted key must be present")
	require.Nil(t, p.peek("b"), "LRU key must be evicted under cap")
}

// peek returns the cached limiter for host without touching its lastAccess
// timestamp. Test-only helper; not on the public API.
func (p *Pool) peek(host string) *ratelimit.Limiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[host]; ok {
		return e.limiter
	}
	return nil
}

// TestPool_TakeBlocksUntilToken verifies end-to-end behavior: with a tight
// budget of 1 token per long interval, two consecutive Takes must observe
// the bucket draining (the second Take blocks until the next refill).
func TestPool_TakeBlocksUntilToken(t *testing.T) {
	p := NewPool(context.Background(), Options{MaxCount: 1, Duration: 50 * time.Millisecond})
	defer p.Stop()

	const host = "h"
	p.Take(host)

	start := time.Now()
	p.Take(host)
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 25*time.Millisecond,
		"second Take should wait for the bucket to refill (got %v)", elapsed)
}

// TestPool_DoesNotEvictEntriesWithWaiters verifies that neither the idle
// sweep nor the LRU cap can reclaim a limiter while goroutines are blocked
// inside its Take(). Without the in-flight guard, a host with a long refill
// window would look idle, get Stop()-ed, and the next access would recreate
// a fresh bucket with full tokens - silently breaking the per-host limit.
func TestPool_DoesNotEvictEntriesWithWaiters(t *testing.T) {
	p := NewPool(context.Background(), Options{
		MaxCount:      1,
		Duration:      300 * time.Millisecond,
		Inactivity:    30 * time.Millisecond, // shorter than the refill wait
		SweepInterval: 10 * time.Millisecond,
		MaxHosts:      1, // force LRU pressure from the second host
	})
	defer p.Stop()

	const blockedHost = "blocked.example.com"
	p.Take(blockedHost) // drain the single token

	// This Take blocks ~300ms waiting for the refill, far longer than the
	// 30ms inactivity window, so the sweep would normally consider the
	// entry idle.
	done := make(chan struct{})
	go func() {
		p.Take(blockedHost)
		close(done)
	}()

	// Give the waiter time to block, then create LRU pressure and let
	// several sweep cycles run.
	time.Sleep(50 * time.Millisecond)
	p.Take("other.example.com")
	time.Sleep(50 * time.Millisecond)

	require.NotNil(t, p.peek(blockedHost),
		"entry with a blocked waiter must not be evicted by sweep or LRU")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Take never completed; limiter was likely stopped under the waiter")
	}
}

// TestPool_StopDrainsAllLimiters verifies Stop() closes every cached limiter
// so no per-host goroutine survives shutdown.
func TestPool_StopDrainsAllLimiters(t *testing.T) {
	p := NewPool(context.Background(), Options{MaxCount: 10, Duration: time.Second})

	const N = 16
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.Take(uniqueHost(i))
		}(i)
	}
	wg.Wait()
	require.Equal(t, N, p.Len())

	p.Stop()

	require.Equal(t, 0, p.Len(), "Stop must drain all entries")
	p.mu.Lock()
	stopped := p.stoppedLimiters
	p.mu.Unlock()
	require.GreaterOrEqual(t, stopped, uint64(N),
		"every cached limiter must be Stop()-ed")

	// Calling Stop again must be safe.
	require.NotPanics(t, p.Stop)
}

// TestPool_NoGoroutineLeak is the strict counterpart of the eviction test:
// cycling through many short-lived hosts and stopping the pool must not leak
// goroutines beyond a small fixed slack. This is the canary that protects
// against future regressions where eviction silently forgets to Stop the
// per-host limiter.
func TestPool_NoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	for round := 0; round < 3; round++ {
		p := NewPool(context.Background(), Options{
			MaxCount:      10,
			Duration:      time.Second,
			Inactivity:    20 * time.Millisecond,
			SweepInterval: 10 * time.Millisecond,
			MaxHosts:      8,
		})
		for i := 0; i < 50; i++ {
			p.Take(uniqueHost(i))
		}
		// Let the sweep run a few times so eviction-driven Stops fire,
		// then drain the rest via Stop().
		time.Sleep(80 * time.Millisecond)
		p.Stop()
	}

	after := waitForGoroutineCount(before+2, 2000)
	require.LessOrEqual(t, after, before+2,
		"per-host limiter goroutines leaked: before=%d after=%d", before, after)
}

func uniqueHost(i int) string {
	// keep allocations simple; avoid fmt to minimize unrelated noise in
	// the goroutine-leak test
	return "h-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func waitForGoroutineCount(target, maxWaitMs int) int {
	for waited := 0; waited < maxWaitMs; waited += 50 {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= target {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}
