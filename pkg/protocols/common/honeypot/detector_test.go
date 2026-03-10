package honeypot

import (
	"fmt"
	"sync"
	"testing"
)

// TestDetectorNormalHost verifies that normal hosts are not flagged as honeypots
func TestDetectorNormalHost(t *testing.T) {
	detector := New(Config{
		Threshold: 20,
	})
	
	host := "normal-host.com"
	
	// Record a few matches (below threshold)
	for i := 0; i < 10; i++ {
		triggered := detector.RecordMatch(host, "template-"+fmt.Sprintf("%d", i))
		if triggered {
			t.Errorf("Expected no honeypot detection for normal host, but was triggered at %d matches", i+1)
		}
	}
	
	// Verify host is not flagged
	if detector.IsHoneypot(host) {
		t.Error("Normal host should not be flagged as honeypot")
	}
	
	// Verify match count
	count := detector.GetMatchCount(host)
	if count != 10 {
		t.Errorf("Expected 10 matches, got %d", count)
	}
	
	// Verify score is below 100
	score := detector.GetScore(host)
	if score >= 100 {
		t.Errorf("Expected score < 100 for normal host, got %d", score)
	}
}

// TestDetectorHoneypotTriggered verifies that honeypots are detected when threshold is exceeded
func TestDetectorHoneypotTriggered(t *testing.T) {
	honeypotDetected := false
	detectedHost := ""
	detectedCount := 0
	
	detector := New(Config{
		Threshold: 20,
		OnHoneypotDetected: func(host string, matchCount int) {
			honeypotDetected = true
			detectedHost = host
			detectedCount = matchCount
		},
	})
	
	host := "honeypot.example.com"
	
	// Record matches up to threshold
	for i := 0; i < 19; i++ {
		triggered := detector.RecordMatch(host, "template-"+fmt.Sprintf("%d", i))
		if triggered {
			t.Errorf("Should not trigger before reaching threshold at match %d", i+1)
		}
	}
	
	// Record the match that triggers detection
	triggered := detector.RecordMatch(host, "template-trigger")
	if !triggered {
		t.Error("Expected honeypot detection to trigger at threshold")
	}
	
	// Verify callback was invoked
	if !honeypotDetected {
		t.Error("Honeypot detection callback was not invoked")
	}
	
	if detectedHost != host {
		t.Errorf("Expected detected host %s, got %s", host, detectedHost)
	}
	
	if detectedCount != 20 {
		t.Errorf("Expected detected count 20, got %d", detectedCount)
	}
	
	// Verify host is flagged
	if !detector.IsHoneypot(host) {
		t.Error("Host should be flagged as honeypot")
	}
	
	// Verify score is at or above 100
	score := detector.GetScore(host)
	if score < 100 {
		t.Errorf("Expected score >= 100 for honeypot, got %d", score)
	}
	
	// Recording more matches should not trigger again
	triggered = detector.RecordMatch(host, "another-template")
	if triggered {
		t.Error("Should not trigger detection again for already flagged host")
	}
}

// TestDetectorConcurrencySafe verifies the detector is thread-safe under concurrent access
func TestDetectorConcurrencySafe(t *testing.T) {
	detector := New(Config{
		Threshold: 50,
	})
	
	const (
		numGoroutines = 100
		matchesPerGoroutine = 10
	)
	
	host := "concurrent-test.com"
	var wg sync.WaitGroup
	
	// Launch many goroutines to record matches concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < matchesPerGoroutine; j++ {
				templateID := "template-" + string(rune(goroutineID*matchesPerGoroutine+j))
				detector.RecordMatch(host, templateID)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify all matches were recorded
	count := detector.GetMatchCount(host)
	expected := numGoroutines * matchesPerGoroutine
	if count != expected {
		t.Errorf("Expected %d matches, got %d (possible race condition)", expected, count)
	}
	
	// Since we exceeded threshold (50), host should be flagged
	if !detector.IsHoneypot(host) {
		t.Error("Host should be flagged as honeypot after exceeding threshold")
	}
}

// TestDetectorThresholdEdgeCase tests behavior exactly at threshold boundary
func TestDetectorThresholdEdgeCase(t *testing.T) {
	threshold := 5
	detector := New(Config{
		Threshold: threshold,
	})
	
	host := "edge-case.com"
	
	// Add matches up to threshold - 1
	for i := 0; i < threshold-1; i++ {
		triggered := detector.RecordMatch(host, "template-"+fmt.Sprintf("%d", i))
		if triggered {
			t.Errorf("Should not trigger at match %d (threshold is %d)", i+1, threshold)
		}
		
		if detector.IsHoneypot(host) {
			t.Errorf("Host should not be flagged at %d matches (threshold is %d)", i+1, threshold)
		}
	}
	
	// Add the exact match that hits threshold
	triggered := detector.RecordMatch(host, "template-threshold")
	if !triggered {
		t.Errorf("Should trigger exactly at threshold (%d)", threshold)
	}
	
	if !detector.IsHoneypot(host) {
		t.Error("Host should be flagged at threshold")
	}
}

// TestDetectorMultipleHosts verifies independent tracking of multiple hosts
func TestDetectorMultipleHosts(t *testing.T) {
	detector := New(Config{
		Threshold: 10,
	})
	
	hosts := []string{"host1.com", "host2.com", "host3.com"}
	
	// Record different numbers of matches for each host
	for i, host := range hosts {
		matchCount := (i + 1) * 5 // 5, 10, 15 matches respectively
		for j := 0; j < matchCount; j++ {
			detector.RecordMatch(host, "template-"+string(rune(j)))
		}
	}
	
	// Verify host1 (5 matches) is not flagged
	if detector.IsHoneypot(hosts[0]) {
		t.Error("host1 should not be flagged (5 matches < threshold 10)")
	}
	
	// Verify host2 (10 matches) is flagged
	if !detector.IsHoneypot(hosts[1]) {
		t.Error("host2 should be flagged (10 matches >= threshold 10)")
	}
	
	// Verify host3 (15 matches) is flagged
	if !detector.IsHoneypot(hosts[2]) {
		t.Error("host3 should be flagged (15 matches >= threshold 10)")
	}
	
	// Verify match counts
	counts := []int{5, 10, 15}
	for i, host := range hosts {
		count := detector.GetMatchCount(host)
		if count != counts[i] {
			t.Errorf("Expected %d matches for %s, got %d", counts[i], host, count)
		}
	}
}

// TestDetectorReset verifies that Reset clears all data
func TestDetectorReset(t *testing.T) {
	detector := New(Config{
		Threshold: 10,
	})
	
	host := "test-host.com"
	
	// Record matches and flag as honeypot
	for i := 0; i < 15; i++ {
		detector.RecordMatch(host, "template-"+fmt.Sprintf("%d", i))
	}
	
	if !detector.IsHoneypot(host) {
		t.Error("Host should be flagged before reset")
	}
	
	// Reset the detector
	detector.Reset()
	
	// Verify all data is cleared
	if detector.IsHoneypot(host) {
		t.Error("Host should not be flagged after reset")
	}
	
	if detector.GetMatchCount(host) != 0 {
		t.Error("Match count should be 0 after reset")
	}
	
	stats := detector.GetStats()
	if stats.TotalHosts != 0 || stats.FlaggedHosts != 0 {
		t.Errorf("Stats should be empty after reset, got: %+v", stats)
	}
}

// TestDetectorDuplicateMatches verifies that duplicate template matches are not double-counted
func TestDetectorDuplicateMatches(t *testing.T) {
	detector := New(Config{
		Threshold: 10,
	})
	
	host := "duplicate-test.com"
	templateID := "same-template"
	
	// Record the same template multiple times
	for i := 0; i < 20; i++ {
		detector.RecordMatch(host, templateID)
	}
	
	// Should only count as 1 match
	count := detector.GetMatchCount(host)
	if count != 1 {
		t.Errorf("Expected 1 unique match despite 20 records, got %d", count)
	}
	
	// Should not be flagged since only 1 unique template
	if detector.IsHoneypot(host) {
		t.Error("Host should not be flagged with only 1 unique template match")
	}
}

// TestDetectorEmptyInputs verifies handling of empty/invalid inputs
func TestDetectorEmptyInputs(t *testing.T) {
	detector := New(Config{
		Threshold: 10,
	})
	
	// Empty host
	triggered := detector.RecordMatch("", "template-1")
	if triggered {
		t.Error("Should not trigger with empty host")
	}
	
	// Empty template
	triggered = detector.RecordMatch("host.com", "")
	if triggered {
		t.Error("Should not trigger with empty template")
	}
	
	// Both empty
	triggered = detector.RecordMatch("", "")
	if triggered {
		t.Error("Should not trigger with both empty")
	}
	
	// Verify no data was recorded
	stats := detector.GetStats()
	if stats.TotalHosts != 0 {
		t.Error("Should not record any hosts with empty inputs")
	}
}

// TestDetectorThresholdUpdate verifies dynamic threshold updates
func TestDetectorThresholdUpdate(t *testing.T) {
	detector := New(Config{
		Threshold: 20,
	})
	
	if detector.GetThreshold() != 20 {
		t.Error("Initial threshold should be 20")
	}
	
	// Update threshold
	detector.SetThreshold(50)
	
	if detector.GetThreshold() != 50 {
		t.Error("Threshold should be updated to 50")
	}
	
	// Invalid threshold (should be ignored)
	detector.SetThreshold(-10)
	if detector.GetThreshold() != 50 {
		t.Error("Invalid threshold should be ignored")
	}
}

// TestDetectorGetStats verifies statistics reporting
func TestDetectorGetStats(t *testing.T) {
	detector := New(Config{
		Threshold: 5,
	})
	
	// Add matches for multiple hosts
	hosts := map[string]int{
		"host1.com": 3,
		"host2.com": 7,
		"host3.com": 10,
	}
	
	for host, count := range hosts {
		for i := 0; i < count; i++ {
			detector.RecordMatch(host, "template-"+fmt.Sprintf("%d", i))
		}
	}
	
	stats := detector.GetStats()
	
	// Verify total hosts
	if stats.TotalHosts != 3 {
		t.Errorf("Expected 3 total hosts, got %d", stats.TotalHosts)
	}
	
	// Verify flagged hosts (host2 and host3 should be flagged with threshold=5)
	if stats.FlaggedHosts != 2 {
		t.Errorf("Expected 2 flagged hosts, got %d", stats.FlaggedHosts)
	}
	
	// Verify individual host counts
	for host, expectedCount := range hosts {
		actualCount, exists := stats.Hosts[host]
		if !exists {
			t.Errorf("Host %s not found in stats", host)
		}
		if actualCount != expectedCount {
			t.Errorf("Expected %d matches for %s, got %d", expectedCount, host, actualCount)
		}
	}
}

// Benchmark tests
func BenchmarkDetectorRecordMatch(b *testing.B) {
	detector := New(Config{
		Threshold: 1000,
	})
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			detector.RecordMatch("benchmark-host.com", "template-"+string(rune(i%100)))
			i++
		}
	})
}

func BenchmarkDetectorIsHoneypot(b *testing.B) {
	detector := New(Config{
		Threshold: 1000,
	})
	
	// Pre-populate with some data
	for i := 0; i < 100; i++ {
		detector.RecordMatch("test-host.com", "template-"+fmt.Sprintf("%d", i))
	}
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			detector.IsHoneypot("test-host.com")
		}
	})
}
