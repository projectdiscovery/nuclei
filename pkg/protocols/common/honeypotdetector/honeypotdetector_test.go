package honeypotdetector

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectorThreshold(t *testing.T) {
	detector := New(3, 100)
	defer detector.Close()

	host := "example.com"

	// First two matches should not trigger detection
	require.False(t, detector.RecordMatch(host, "template-1"))
	require.False(t, detector.RecordMatch(host, "template-2"))
	require.False(t, detector.IsHoneypot(host))
	require.Equal(t, 2, detector.GetMatchCount(host))

	// Third match should trigger detection
	require.True(t, detector.RecordMatch(host, "template-3"))
	require.True(t, detector.IsHoneypot(host))
	require.Equal(t, 3, detector.GetMatchCount(host))
	require.Equal(t, 1, detector.GetHoneypotCount())

	// Additional matches should still return true
	require.True(t, detector.RecordMatch(host, "template-4"))
}

func TestDetectorDuplicateTemplates(t *testing.T) {
	detector := New(3, 100)
	defer detector.Close()

	host := "example.com"

	// Recording the same template multiple times should not increment count
	detector.RecordMatch(host, "template-1")
	detector.RecordMatch(host, "template-1")
	detector.RecordMatch(host, "template-1")

	require.Equal(t, 1, detector.GetMatchCount(host))
	require.False(t, detector.IsHoneypot(host))
}

func TestDetectorMultipleHosts(t *testing.T) {
	detector := New(2, 100)
	defer detector.Close()

	// Host A gets flagged
	detector.RecordMatch("host-a.com", "template-1")
	detector.RecordMatch("host-a.com", "template-2")

	// Host B does not get flagged
	detector.RecordMatch("host-b.com", "template-1")

	require.True(t, detector.IsHoneypot("host-a.com"))
	require.False(t, detector.IsHoneypot("host-b.com"))
	require.Equal(t, 1, detector.GetHoneypotCount())
}

func TestDetectorEdgeCases(t *testing.T) {
	detector := New(5, 100)
	defer detector.Close()

	// Empty strings should not cause issues
	require.False(t, detector.RecordMatch("", "template-1"))
	require.False(t, detector.RecordMatch("host.com", ""))
	require.False(t, detector.RecordMatch("", ""))

	require.False(t, detector.IsHoneypot(""))
	require.Equal(t, 0, detector.GetMatchCount(""))
	require.Equal(t, 0, detector.GetMatchCount("nonexistent.com"))
}

func TestDetectorConcurrent(t *testing.T) {
	detector := New(100, 1000)
	defer detector.Close()

	var wg sync.WaitGroup
	host := "concurrent-test.com"

	// Spawn 50 goroutines each recording 10 different templates
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				templateID := "template-" + string(rune('A'+workerID)) + "-" + string(rune('0'+j))
				detector.RecordMatch(host, templateID)
			}
		}(i)
	}

	wg.Wait()

	// Should have detected honeypot (50 * 10 = 500 distinct templates > 100 threshold)
	require.True(t, detector.IsHoneypot(host))
	require.GreaterOrEqual(t, detector.GetMatchCount(host), 100)
}

func TestDetectorConcurrentMultipleHosts(t *testing.T) {
	detector := New(5, 1000)
	defer detector.Close()

	var wg sync.WaitGroup

	// Test concurrent access across multiple hosts
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(hostID int) {
			defer wg.Done()
			host := "host-" + string(rune('A'+hostID)) + ".com"
			for j := 0; j < 10; j++ {
				templateID := "template-" + string(rune('0'+j))
				detector.RecordMatch(host, templateID)
			}
		}(i)
	}

	wg.Wait()

	// All 20 hosts should be flagged (each has 10 templates > 5 threshold)
	require.Equal(t, 20, detector.GetHoneypotCount())
}

func TestDetectorGetFlaggedHosts(t *testing.T) {
	detector := New(2, 100)
	defer detector.Close()

	// Flag two hosts
	detector.RecordMatch("flagged-1.com", "t1")
	detector.RecordMatch("flagged-1.com", "t2")
	detector.RecordMatch("flagged-2.com", "t1")
	detector.RecordMatch("flagged-2.com", "t2")

	// One host not flagged
	detector.RecordMatch("clean.com", "t1")

	flagged := detector.GetFlaggedHosts()
	require.Len(t, flagged, 2)
	require.Contains(t, flagged, "flagged-1.com")
	require.Contains(t, flagged, "flagged-2.com")
	require.NotContains(t, flagged, "clean.com")
}

func TestDetectorLRUEviction(t *testing.T) {
	// Small cache to test eviction
	detector := New(5, 3)
	defer detector.Close()

	// Add 4 hosts to trigger eviction of the first
	detector.RecordMatch("host-1.com", "t1")
	detector.RecordMatch("host-2.com", "t1")
	detector.RecordMatch("host-3.com", "t1")
	detector.RecordMatch("host-4.com", "t1")

	// host-1 should have been evicted
	require.Equal(t, 0, detector.GetMatchCount("host-1.com"))
}

func TestDetectorDefaultValues(t *testing.T) {
	// Test with zero/negative values uses defaults
	detector := New(0, 0)
	defer detector.Close()

	// Should use DefaultThreshold (10)
	for i := 0; i < 9; i++ {
		require.False(t, detector.RecordMatch("test.com", "template-"+string(rune('A'+i))))
	}
	// 10th should trigger
	require.True(t, detector.RecordMatch("test.com", "template-J"))
}
