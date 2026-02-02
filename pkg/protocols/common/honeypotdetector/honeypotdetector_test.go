// Package honeypotdetector provides tests for the honeypot detection system.
// These tests verify threshold behavior, blocklist loading, LRU eviction,
// concurrent access safety, and various edge cases.
package honeypotdetector

import (
	"os"
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

func TestDetectorLoadBlocklist(t *testing.T) {
	// Create a temporary blocklist file
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/blocklist.txt"

	// Write test blocklist with comments and blank lines
	content := `# Known honeypots
honeypot1.com
honeypot2.com

# More honeypots
192.168.1.1
`
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	// Load blocklist
	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 3, count)

	// Pre-flagged hosts should be detected as honeypots immediately
	require.True(t, detector.IsHoneypot("honeypot1.com"))
	require.True(t, detector.IsHoneypot("honeypot2.com"))
	require.True(t, detector.IsHoneypot("192.168.1.1"))

	// Unknown hosts should not be honeypots
	require.False(t, detector.IsHoneypot("clean-host.com"))

	// Honeypot count should reflect loaded hosts
	require.Equal(t, 3, detector.GetHoneypotCount())
}

func TestDetectorLoadBlocklistFileNotFound(t *testing.T) {
	detector := New(10, 100)
	defer detector.Close()

	// Non-existent file should return error
	_, err := detector.LoadBlocklist("/nonexistent/path/blocklist.txt")
	require.Error(t, err)
}

func TestDetectorLoadBlocklistCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/blocklist.txt"

	// Write blocklist with mixed case
	content := "HONEYPOT.COM\nMixedCase.Net\n"
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	// Should match case-insensitively due to lowercase normalization
	require.True(t, detector.IsHoneypot("honeypot.com"))
	require.True(t, detector.IsHoneypot("mixedcase.net"))
}

func TestDetectorPreFlaggedHostStillTracksTemplates(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/blocklist.txt"

	// Pre-flag a host
	content := "preflagged.com\n"
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	detector.LoadBlocklist(blocklistPath)

	// Record additional matches after loading blocklist
	detector.RecordMatch("preflagged.com", "template-1")
	detector.RecordMatch("preflagged.com", "template-2")

	// Should still track templates beyond the blocklist marker
	require.True(t, detector.IsHoneypot("preflagged.com"))
	require.GreaterOrEqual(t, detector.GetMatchCount("preflagged.com"), 2)
}

func TestDetectorEmptyBlocklist(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/empty.txt"

	// Write empty blocklist (only comments)
	content := "# This is a comment\n\n# Another comment\n"
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 0, count)
	require.Equal(t, 0, detector.GetHoneypotCount())
}

func TestDetectorLoadBlocklistDuplicateHosts(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/duplicates.txt"

	// Write blocklist with duplicates
	content := "duplicate.com\nduplicate.com\nduplicate.com\nunique.com\n"
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	// Loads 4 lines but should only count 2 unique hosts
	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 4, count) // 4 lines read

	// But only 2 unique honeypots flagged
	require.Equal(t, 2, detector.GetHoneypotCount())
}

func TestDetectorThresholdBoundary(t *testing.T) {
	// Test exact threshold boundary behavior
	detector := New(5, 100)
	defer detector.Close()

	host := "boundary.com"

	// 4 templates: not honeypot
	for i := 0; i < 4; i++ {
		require.False(t, detector.RecordMatch(host, "t-"+string(rune('A'+i))))
	}
	require.False(t, detector.IsHoneypot(host))
	require.Equal(t, 4, detector.GetMatchCount(host))

	// 5th template: becomes honeypot
	require.True(t, detector.RecordMatch(host, "t-E"))
	require.True(t, detector.IsHoneypot(host))
	require.Equal(t, 5, detector.GetMatchCount(host))
}

func TestDetectorVerboseMode(t *testing.T) {
	detector := New(2, 100)
	defer detector.Close()

	// Enable verbose mode
	detector.SetVerbose(true)

	// Should not panic with verbose logging
	detector.RecordMatch("verbose.com", "t1")
	detector.RecordMatch("verbose.com", "t2")

	require.True(t, detector.IsHoneypot("verbose.com"))
}

func TestDetectorStatsAccuracy(t *testing.T) {
	detector := New(3, 100)
	defer detector.Close()

	// Create 5 honeypots
	for i := 0; i < 5; i++ {
		host := "host-" + string(rune('A'+i)) + ".com"
		for j := 0; j < 3; j++ {
			detector.RecordMatch(host, "template-"+string(rune('0'+j)))
		}
	}

	require.Equal(t, 5, detector.GetHoneypotCount())
	require.Len(t, detector.GetFlaggedHosts(), 5)
}

func TestDetectorRecordMatchAfterFlagged(t *testing.T) {
	// Test that recording matches after flagged still returns true
	detector := New(2, 100)
	defer detector.Close()

	detector.RecordMatch("test.com", "t1")
	detector.RecordMatch("test.com", "t2") // Flagged here

	// Additional matches should still return true
	require.True(t, detector.RecordMatch("test.com", "t3"))
	require.True(t, detector.RecordMatch("test.com", "t4"))
	require.Equal(t, 4, detector.GetMatchCount("test.com"))
}

func TestDetectorIsHoneypotBeforeRecord(t *testing.T) {
	detector := New(5, 100)
	defer detector.Close()

	// Unknown host should not be honeypot
	require.False(t, detector.IsHoneypot("unknown.com"))
	require.Equal(t, 0, detector.GetMatchCount("unknown.com"))
}

func TestDetectorGetFlaggedHostsEmpty(t *testing.T) {
	detector := New(10, 100)
	defer detector.Close()

	// No hosts flagged
	flagged := detector.GetFlaggedHosts()
	require.Empty(t, flagged)
}

func TestDetectorGetFlaggedHostsPartial(t *testing.T) {
	detector := New(3, 100)
	defer detector.Close()

	// Host A: 3 templates (flagged)
	detector.RecordMatch("flagged.com", "t1")
	detector.RecordMatch("flagged.com", "t2")
	detector.RecordMatch("flagged.com", "t3")

	// Host B: 2 templates (not flagged)
	detector.RecordMatch("clean.com", "t1")
	detector.RecordMatch("clean.com", "t2")

	flagged := detector.GetFlaggedHosts()
	require.Len(t, flagged, 1)
	require.Contains(t, flagged, "flagged.com")
	require.NotContains(t, flagged, "clean.com")
}

func TestDetectorClosePurgesCache(t *testing.T) {
	detector := New(2, 100)

	detector.RecordMatch("test.com", "t1")
	detector.RecordMatch("test.com", "t2")
	require.True(t, detector.IsHoneypot("test.com"))

	detector.Close()

	// After close, cache is purged
	require.False(t, detector.IsHoneypot("test.com"))
	require.Equal(t, 0, detector.GetMatchCount("test.com"))
}

func TestDetectorMultipleBlocklistLoads(t *testing.T) {
	tmpDir := t.TempDir()

	detector := New(10, 100)
	defer detector.Close()

	// First blocklist
	blocklist1 := tmpDir + "/blocklist1.txt"
	require.NoError(t, os.WriteFile(blocklist1, []byte("host1.com\nhost2.com\n"), 0644))

	count1, err := detector.LoadBlocklist(blocklist1)
	require.NoError(t, err)
	require.Equal(t, 2, count1)

	// Second blocklist
	blocklist2 := tmpDir + "/blocklist2.txt"
	require.NoError(t, os.WriteFile(blocklist2, []byte("host3.com\nhost4.com\n"), 0644))

	count2, err := detector.LoadBlocklist(blocklist2)
	require.NoError(t, err)
	require.Equal(t, 2, count2)

	// All 4 should be honeypots
	require.Equal(t, 4, detector.GetHoneypotCount())
	require.True(t, detector.IsHoneypot("host1.com"))
	require.True(t, detector.IsHoneypot("host4.com"))
}

func TestDetectorBlocklistWithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/whitespace.txt"

	// Blocklist with extra whitespace
	content := "  host1.com  \n\thost2.com\t\n   \n"
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	require.True(t, detector.IsHoneypot("host1.com"))
	require.True(t, detector.IsHoneypot("host2.com"))
}

func TestDetectorConcurrentBlocklistAndRecord(t *testing.T) {
	detector := New(5, 1000)
	defer detector.Close()

	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/concurrent.txt"
	require.NoError(t, os.WriteFile(blocklistPath, []byte("blocked.com\n"), 0644))

	var wg sync.WaitGroup

	// Concurrent blocklist load
	wg.Add(1)
	go func() {
		defer wg.Done()
		detector.LoadBlocklist(blocklistPath)
	}()

	// Concurrent record matches
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			host := "host-" + string(rune('A'+id)) + ".com"
			for j := 0; j < 5; j++ {
				detector.RecordMatch(host, "t-"+string(rune('0'+j)))
			}
		}(i)
	}

	wg.Wait()

	// Should not crash, blocked host should be honeypot
	require.True(t, detector.IsHoneypot("blocked.com"))
}

func TestDetectorHighThreshold(t *testing.T) {
	detector := New(100, 1000)
	defer detector.Close()

	host := "high-threshold.com"

	// 99 templates: not flagged
	for i := 0; i < 99; i++ {
		detector.RecordMatch(host, "template-"+string(rune(i)))
	}
	require.False(t, detector.IsHoneypot(host))
	require.Equal(t, 99, detector.GetMatchCount(host))

	// 100th: flagged
	require.True(t, detector.RecordMatch(host, "template-final"))
	require.True(t, detector.IsHoneypot(host))
}

func TestDetectorThresholdOne(t *testing.T) {
	// Edge case: threshold of 1 means first match flags
	detector := New(1, 100)
	defer detector.Close()

	require.True(t, detector.RecordMatch("instant.com", "t1"))
	require.True(t, detector.IsHoneypot("instant.com"))
	require.Equal(t, 1, detector.GetHoneypotCount())
}

func TestDetectorLRUEvictionDecrementsCount(t *testing.T) {
	// Create detector with small cache to force evictions
	detector := New(2, 5) // threshold=2, maxHosts=5
	defer detector.Close()

	// Fill cache with 5 flagged hosts
	for i := 0; i < 5; i++ {
		host := "host" + string(rune('A'+i)) + ".com"
		detector.RecordMatch(host, "t1")
		detector.RecordMatch(host, "t2") // Flags as honeypot
	}

	// All 5 should be flagged
	require.Equal(t, 5, detector.GetHoneypotCount())

	// Add 3 more hosts to force evictions of first 3
	for i := 0; i < 3; i++ {
		host := "new" + string(rune('A'+i)) + ".com"
		detector.RecordMatch(host, "t1")
		detector.RecordMatch(host, "t2")
	}

	// Should have evicted 3 old flagged hosts, count should be 5 (5-3+3)
	require.Equal(t, 5, detector.GetHoneypotCount())
	require.Len(t, detector.GetFlaggedHosts(), 5)
}

func TestDetectorLRUEvictionNonFlaggedNotDecremented(t *testing.T) {
	// Test that non-flagged evictions don't affect count
	detector := New(3, 3) // threshold=3, maxHosts=3
	defer detector.Close()

	// Add 3 non-flagged hosts (only 1 template each)
	detector.RecordMatch("host1.com", "t1")
	detector.RecordMatch("host2.com", "t1")
	detector.RecordMatch("host3.com", "t1")

	require.Equal(t, 0, detector.GetHoneypotCount())

	// Add a 4th host (evicts host1.com) - still no honeypots
	detector.RecordMatch("host4.com", "t1")
	require.Equal(t, 0, detector.GetHoneypotCount())

	// Now flag one host
	detector.RecordMatch("host4.com", "t2")
	detector.RecordMatch("host4.com", "t3")
	require.Equal(t, 1, detector.GetHoneypotCount())
}

func TestDetectorLoadBlocklistCSVFormat(t *testing.T) {
	// Test that exported CSV format can be re-imported as blocklist
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/exported.txt"

	// Simulate exported CSV format with header comments
	content := `# Honeypot hosts detected by nuclei
# Format: host,match_count
honeypot1.com,15
honeypot2.com,23
192.168.1.100,8
`
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 3, count)

	// All three hosts should be recognized (CSV parsed correctly)
	require.True(t, detector.IsHoneypot("honeypot1.com"))
	require.True(t, detector.IsHoneypot("honeypot2.com"))
	require.True(t, detector.IsHoneypot("192.168.1.100"))
}

func TestDetectorLoadBlocklistMixedFormat(t *testing.T) {
	// Test mixed format: plain hosts and CSV
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/mixed.txt"

	content := `# Mixed format file
plain-host.com
csv-host.com,42
another-plain.com
`
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 3, count)

	require.True(t, detector.IsHoneypot("plain-host.com"))
	require.True(t, detector.IsHoneypot("csv-host.com"))
	require.True(t, detector.IsHoneypot("another-plain.com"))
}

func TestDetectorCaseInsensitiveMatching(t *testing.T) {
	// Test that blocklist entries match regardless of case
	tmpDir := t.TempDir()
	blocklistPath := tmpDir + "/blocklist.txt"

	// Blocklist with uppercase entries
	content := `HONEYPOT.COM
MixedCase.Example.COM
`
	require.NoError(t, os.WriteFile(blocklistPath, []byte(content), 0644))

	detector := New(10, 100)
	defer detector.Close()

	count, err := detector.LoadBlocklist(blocklistPath)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	// All case variations should match
	require.True(t, detector.IsHoneypot("honeypot.com"))
	require.True(t, detector.IsHoneypot("HONEYPOT.COM"))
	require.True(t, detector.IsHoneypot("Honeypot.Com"))
	require.True(t, detector.IsHoneypot("mixedcase.example.com"))
	require.True(t, detector.IsHoneypot("MIXEDCASE.EXAMPLE.COM"))
}

func TestDetectorRecordMatchCaseInsensitive(t *testing.T) {
	// Test that RecordMatch normalizes host case
	detector := New(2, 100)
	defer detector.Close()

	// Mix case when recording matches
	detector.RecordMatch("EXAMPLE.COM", "t1")
	detector.RecordMatch("example.com", "t2") // Should count as same host

	// Should be flagged via lowercase lookup
	require.True(t, detector.IsHoneypot("example.com"))
	require.True(t, detector.IsHoneypot("EXAMPLE.COM"))
	require.True(t, detector.IsHoneypot("Example.Com"))

	// Match count should be 2 (both templates on same normalized host)
	require.Equal(t, 2, detector.GetMatchCount("example.com"))
	require.Equal(t, 2, detector.GetMatchCount("EXAMPLE.COM"))
}
