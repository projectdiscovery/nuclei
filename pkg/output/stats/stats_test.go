package stats

import (
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Bounded scheduler stress for counter creation: every iteration uses a fresh
// tracker, so the key is always seen for the first time while workers are
// released together. The assertion is exact, so a fixed build never retries or
// sleeps; an unfixed build drops increments on the racing first hits.
const (
	concurrentFirstHitWorkers    = 64
	concurrentFirstHitIterations = 200
)

// releaseTogether runs fn in n goroutines that all start on one signal.
func releaseTogether(n int, fn func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			fn()
		}()
	}
	close(start)
	wg.Wait()
}

// requireMultipleP raises P above one so the racing window is reachable on
// small runners. It records the machine's real shape and does not claim that a
// single-P run cannot interleave: the scheduler may still preempt mid-window.
func requireMultipleP(t *testing.T) {
	t.Helper()
	t.Logf("scheduler shape: runtime.NumCPU=%d GOMAXPROCS=%d", runtime.NumCPU(), runtime.GOMAXPROCS(0))
	if runtime.GOMAXPROCS(0) < 2 {
		previous := runtime.GOMAXPROCS(4)
		t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	}
}

func TestTrackStatusCodeConcurrentFirstHit(t *testing.T) {
	requireMultipleP(t)

	for iteration := 0; iteration < concurrentFirstHitIterations; iteration++ {
		tracker := NewTracker()
		releaseTogether(concurrentFirstHitWorkers, func() { tracker.TrackStatusCode("200") })

		require.Equalf(t, concurrentFirstHitWorkers, tracker.GetStats().StatusCodeStats["200"],
			"iteration %d: concurrent first hits on status code 200 lost increments", iteration)
	}
}

func TestTrackErrorKindConcurrentFirstHit(t *testing.T) {
	requireMultipleP(t)

	for iteration := 0; iteration < concurrentFirstHitIterations; iteration++ {
		tracker := NewTracker()
		releaseTogether(concurrentFirstHitWorkers, func() { tracker.TrackErrorKind("timeout") })

		require.Equalf(t, concurrentFirstHitWorkers, tracker.GetStats().ErrorStats["timeout"],
			"iteration %d: concurrent first hits on error kind timeout lost increments", iteration)
	}
}

func TestTrackWAFDetectedConcurrentFirstHit(t *testing.T) {
	requireMultipleP(t)

	const workers = 16
	for iteration := 0; iteration < 20; iteration++ {
		tracker := NewTracker()
		releaseTogether(workers, func() { tracker.TrackWAFDetected("Attention Required! | Cloudflare") })

		// Read through the user-visible accessor, not the internal map: WAFStats
		// is keyed by detector name ("CloudFlare"), while wafDetected is keyed by
		// the detector id ("cloudflare").
		require.Equalf(t, workers, tracker.GetStats().WAFStats["CloudFlare"],
			"iteration %d: concurrent first WAF hits lost increments", iteration)
	}
}

func TestTrackStatusCodeConcurrentThenSequential(t *testing.T) {
	requireMultipleP(t)

	tracker := NewTracker()
	releaseTogether(concurrentFirstHitWorkers, func() { tracker.TrackStatusCode("200") })
	for range 5 {
		tracker.TrackStatusCode("200")
	}

	// Sequential updates must land on the counter that stayed in the map.
	require.Equal(t, concurrentFirstHitWorkers+5, tracker.GetStats().StatusCodeStats["200"])
}

func TestTrackStatusCodeConcurrentExistingKey(t *testing.T) {
	requireMultipleP(t)

	tracker := NewTracker()
	tracker.TrackStatusCode("200")
	releaseTogether(concurrentFirstHitWorkers, func() { tracker.TrackStatusCode("200") })

	require.Equal(t, concurrentFirstHitWorkers+1, tracker.GetStats().StatusCodeStats["200"])
}

func TestTrackStatusCodeConcurrentDistinctKeys(t *testing.T) {
	requireMultipleP(t)

	keys := []string{"200", "201", "204", "301", "302", "400", "401", "403", "404", "500"}
	tracker := NewTracker()

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(len(keys))
	for _, key := range keys {
		go func() {
			defer wg.Done()
			<-start
			tracker.TrackStatusCode(key)
		}()
	}
	close(start)
	wg.Wait()

	stats := tracker.GetStats()
	total := 0
	for _, key := range keys {
		require.Equalf(t, 1, stats.StatusCodeStats[key], "status code %s counted wrong", key)
		total += stats.StatusCodeStats[key]
	}
	require.Equal(t, len(keys), total)
}

func TestTrackErrorKind(t *testing.T) {
	tracker := NewTracker()

	// Test single increment
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind timeout count to be 1, got %v", count)
	}

	// Test multiple increments
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 2 {
		t.Errorf("expected error kind timeout count to be 2, got %v", count)
	}

	// Test different error kind
	tracker.TrackErrorKind("connection-refused")
	if count, _ := tracker.errorCodes.Get("connection-refused"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind connection-refused count to be 1, got %v", count)
	}
}

func TestTrackWaf_Detect(t *testing.T) {
	tracker := NewTracker()

	tracker.TrackWAFDetected("Attention Required! | Cloudflare")
	if count, _ := tracker.wafDetected.Get("cloudflare"); count == nil || count.Load() != 1 {
		t.Errorf("expected waf detected count to be 1, got %v", count)
	}
}

func TestTrackersShareDetectorButNotCounters(t *testing.T) {
	first := NewTracker()
	second := NewTracker()

	require.Same(t, first.wafDetector, second.wafDetector)

	first.TrackStatusCode("200")
	first.TrackErrorKind("timeout")
	first.TrackWAFDetected("Attention Required! | Cloudflare")

	require.Equal(t, 1, first.GetStats().StatusCodeStats["200"])
	require.Equal(t, 1, first.GetStats().ErrorStats["timeout"])
	require.Equal(t, 1, first.GetStats().WAFStats["CloudFlare"])
	require.Empty(t, second.GetStats().StatusCodeStats)
	require.Empty(t, second.GetStats().ErrorStats)
	require.Empty(t, second.GetStats().WAFStats)
}

func TestWAFMetricsAreExecutionLocal(t *testing.T) {
	first := NewTracker()
	second := NewTracker()
	response := "ordinary response with no WAF signature"

	first.TrackWAFDetected(response)

	metrics := first.GetWAFMetrics()
	require.Equal(t, uint64(1), metrics.Calls)
	require.Equal(t, uint64(len(response)), metrics.Bytes)
	require.Greater(t, metrics.PrefilterSkips, uint64(0))
	require.Greater(t, metrics.RegexEvaluations+metrics.PrefilterSkips, uint64(0))
	require.Zero(t, second.GetWAFMetrics().Calls)
}

func TestWAFMetricsAreConcurrencySafe(t *testing.T) {
	tracker := NewTracker()
	response := "ordinary response with no WAF signature"

	const calls = 32
	var wg sync.WaitGroup
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.TrackWAFDetected(response)
		}()
	}
	wg.Wait()

	metrics := tracker.GetWAFMetrics()
	require.Equal(t, uint64(calls), metrics.Calls)
	require.Equal(t, uint64(calls*len(response)), metrics.Bytes)
}
