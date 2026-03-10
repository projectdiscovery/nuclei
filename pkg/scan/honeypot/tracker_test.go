package honeypot

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/gologger"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker(50, nil)
	if tracker.threshold != 50 {
		t.Errorf("expected threshold 50, got %d", tracker.threshold)
	}

	// Test default threshold.
	tracker = NewTracker(0, nil)
	if tracker.threshold != DefaultThreshold {
		t.Errorf("expected default threshold %d, got %d", DefaultThreshold, tracker.threshold)
	}

	// Test negative threshold.
	tracker = NewTracker(-1, nil)
	if tracker.threshold != DefaultThreshold {
		t.Errorf("expected default threshold %d, got %d", DefaultThreshold, tracker.threshold)
	}
}

func TestRecordMatchAndIsHoneypot(t *testing.T) {
	tracker := NewTracker(3, nil)

	// Record matches below threshold.
	flagged := tracker.RecordMatch("http://example.com", "CVE-2021-0001")
	if flagged {
		t.Error("expected host not to be flagged after 1 match")
	}
	if tracker.IsHoneypot("http://example.com") {
		t.Error("expected host not to be a honeypot after 1 match")
	}

	flagged = tracker.RecordMatch("http://example.com", "CVE-2021-0002")
	if flagged {
		t.Error("expected host not to be flagged after 2 matches")
	}

	// Third unique match should trigger flagging.
	flagged = tracker.RecordMatch("http://example.com", "CVE-2021-0003")
	if !flagged {
		t.Error("expected host to be flagged after 3 matches")
	}
	if !tracker.IsHoneypot("http://example.com") {
		t.Error("expected host to be a honeypot after 3 matches")
	}

	// Subsequent matches should not re-trigger (already flagged).
	flagged = tracker.RecordMatch("http://example.com", "CVE-2021-0004")
	if flagged {
		t.Error("expected host not to re-trigger flagging")
	}
}

func TestDuplicateTemplateIDs(t *testing.T) {
	tracker := NewTracker(3, nil)

	// Record the same template multiple times.
	tracker.RecordMatch("http://example.com", "CVE-2021-0001")
	tracker.RecordMatch("http://example.com", "CVE-2021-0001")
	tracker.RecordMatch("http://example.com", "CVE-2021-0001")

	if tracker.GetMatchCount("http://example.com") != 1 {
		t.Errorf("expected 1 unique match, got %d", tracker.GetMatchCount("http://example.com"))
	}
	if tracker.IsHoneypot("http://example.com") {
		t.Error("duplicate template IDs should not trigger honeypot detection")
	}
}

func TestHostNormalization(t *testing.T) {
	tracker := NewTracker(2, nil)

	// Different URL forms for the same host should be tracked together.
	tracker.RecordMatch("http://example.com/path1", "CVE-2021-0001")
	tracker.RecordMatch("https://example.com/path2", "CVE-2021-0002")

	if tracker.GetMatchCount("example.com") != 2 {
		t.Errorf("expected 2 matches for normalized host, got %d", tracker.GetMatchCount("example.com"))
	}
}

func TestHostNormalizationDefaultPorts(t *testing.T) {
	tracker := NewTracker(3, nil)

	tracker.RecordMatch("http://example.com:80", "CVE-2021-0001")
	tracker.RecordMatch("http://example.com", "CVE-2021-0002")

	count := tracker.GetMatchCount("example.com")
	if count != 2 {
		t.Errorf("expected 2 matches (port 80 normalized), got %d", count)
	}
}

func TestMultipleHosts(t *testing.T) {
	tracker := NewTracker(2, nil)

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host1.com", "CVE-2021-0002")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0001")

	if !tracker.IsHoneypot("http://host1.com") {
		t.Error("expected host1 to be flagged as honeypot")
	}
	if tracker.IsHoneypot("http://host2.com") {
		t.Error("expected host2 not to be flagged")
	}
}

func TestGetFlaggedHosts(t *testing.T) {
	tracker := NewTracker(2, nil)

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host1.com", "CVE-2021-0002")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0002")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0003")
	tracker.RecordMatch("http://host3.com", "CVE-2021-0001")

	flagged := tracker.GetFlaggedHosts()
	if len(flagged) != 2 {
		t.Errorf("expected 2 flagged hosts, got %d", len(flagged))
	}

	// Results should be sorted by match count descending.
	if len(flagged) >= 2 {
		if flagged[0].MatchCount < flagged[1].MatchCount {
			t.Error("expected flagged hosts to be sorted by match count descending")
		}
	}
}

func TestPercentageBasedDetection(t *testing.T) {
	tracker := NewTracker(1000, nil) // High absolute threshold.
	tracker.SetTotalTemplates(20)

	// 75% of 20 = 15 templates, so 15 matches should trigger.
	for i := 0; i < 14; i++ {
		tracker.RecordMatch("http://example.com", fmt.Sprintf("template-%d", i))
	}
	if tracker.IsHoneypot("http://example.com") {
		t.Error("expected host not to be flagged at 14/20 matches")
	}

	// 15th match should trigger percentage-based detection.
	flagged := tracker.RecordMatch("http://example.com", "template-14")
	if !flagged {
		t.Error("expected host to be flagged at 15/20 matches (75%)")
	}
}

func TestPercentageBasedDetectionMinimumThreshold(t *testing.T) {
	tracker := NewTracker(1000, nil)
	tracker.SetTotalTemplates(5)

	// Even at 80% (4/5), should not trigger because minimum is 10 matches.
	for i := 0; i < 4; i++ {
		tracker.RecordMatch("http://example.com", fmt.Sprintf("template-%d", i))
	}
	if tracker.IsHoneypot("http://example.com") {
		t.Error("should not trigger percentage detection with fewer than 10 matches")
	}
}

func TestSummary(t *testing.T) {
	tracker := NewTracker(2, nil)

	// No flagged hosts.
	if tracker.Summary() != "" {
		t.Error("expected empty summary with no flagged hosts")
	}

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host1.com", "CVE-2021-0002")

	summary := tracker.Summary()
	if summary == "" {
		t.Error("expected non-empty summary after flagging a host")
	}
}

func TestEmptyInput(t *testing.T) {
	tracker := NewTracker(2, nil)

	flagged := tracker.RecordMatch("", "CVE-2021-0001")
	if flagged {
		t.Error("empty host should not be flagged")
	}

	if tracker.IsHoneypot("") {
		t.Error("empty host should not be a honeypot")
	}

	if tracker.GetMatchCount("") != 0 {
		t.Error("empty host should have 0 match count")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tracker := NewTracker(50, &gologger.Logger{})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			host := fmt.Sprintf("http://host%d.com", idx%5)
			templateID := fmt.Sprintf("CVE-2021-%04d", idx)
			tracker.RecordMatch(host, templateID)
			_ = tracker.IsHoneypot(host)
			_ = tracker.GetMatchCount(host)
		}(i)
	}
	wg.Wait()

	// Just verify no panic occurred and data is consistent.
	total := 0
	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("http://host%d.com", i)
		count := tracker.GetMatchCount(host)
		if count < 0 || count > 100 {
			t.Errorf("unexpected match count %d for %s", count, host)
		}
		total += count
	}
	if total != 100 {
		t.Errorf("expected total 100 unique matches across hosts, got %d", total)
	}
}

func TestMaxHostsLimit(t *testing.T) {
	tracker := NewTracker(100, nil)
	// Override maxHosts to a small value for testing.
	tracker.maxHosts = 3

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host3.com", "CVE-2021-0001")

	// Fourth host should be dropped.
	tracker.RecordMatch("http://host4.com", "CVE-2021-0001")
	if tracker.GetMatchCount("http://host4.com") != 0 {
		t.Error("expected host4 to be dropped due to max hosts limit")
	}

	// Existing hosts should still accept new matches.
	tracker.RecordMatch("http://host1.com", "CVE-2021-0002")
	if tracker.GetMatchCount("http://host1.com") != 2 {
		t.Errorf("expected 2 matches for host1, got %d", tracker.GetMatchCount("http://host1.com"))
	}
}

func TestMaxHostsDroppedCounter(t *testing.T) {
	tracker := NewTracker(100, nil)
	tracker.maxHosts = 2

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0001")

	// These should be dropped and counted.
	tracker.RecordMatch("http://host3.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host4.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host5.com", "CVE-2021-0001")

	dropped := tracker.DroppedHosts()
	if dropped != 3 {
		t.Errorf("expected 3 dropped hosts, got %d", dropped)
	}

	// Summary should include the dropped hosts count.
	summary := tracker.Summary()
	if summary == "" {
		t.Error("expected non-empty summary when hosts are dropped")
	}
	if !strings.Contains(summary, "3 host(s) excluded") {
		t.Errorf("expected summary to mention 3 excluded hosts, got: %s", summary)
	}
	if !strings.Contains(summary, "max hosts limit: 2") {
		t.Errorf("expected summary to mention max hosts limit of 2, got: %s", summary)
	}
}

func TestSummaryDroppedHostsOnly(t *testing.T) {
	// Verify Summary returns content when there are dropped hosts but no flagged hosts.
	tracker := NewTracker(1000, nil) // High threshold so nothing gets flagged.
	tracker.maxHosts = 1

	tracker.RecordMatch("http://host1.com", "CVE-2021-0001")
	tracker.RecordMatch("http://host2.com", "CVE-2021-0001") // Dropped.

	if tracker.DroppedHosts() != 1 {
		t.Errorf("expected 1 dropped host, got %d", tracker.DroppedHosts())
	}

	summary := tracker.Summary()
	if summary == "" {
		t.Error("expected non-empty summary when hosts are dropped (even with no flagged hosts)")
	}
	if !strings.Contains(summary, "1 host(s) excluded") {
		t.Errorf("expected summary to mention excluded hosts, got: %s", summary)
	}
}

func TestShouldFlagReason(t *testing.T) {
	// Test that shouldFlag returns the correct reason.
	tracker := NewTracker(5, nil)

	// Below threshold: not flagged.
	reason := tracker.shouldFlag(3)
	if reason != notFlagged {
		t.Errorf("expected notFlagged for 3 matches, got %v", reason)
	}

	// At absolute threshold: flagAbsolute.
	reason = tracker.shouldFlag(5)
	if reason != flagAbsolute {
		t.Errorf("expected flagAbsolute for 5 matches, got %v", reason)
	}

	// Test percentage-based detection.
	tracker2 := NewTracker(1000, nil) // High absolute threshold.
	tracker2.SetTotalTemplates(20)

	// 14/20 = 70% -- below 75%.
	reason = tracker2.shouldFlag(14)
	if reason != notFlagged {
		t.Errorf("expected notFlagged for 14/20 (70%%), got %v", reason)
	}

	// 15/20 = 75% -- should trigger percentage.
	reason = tracker2.shouldFlag(15)
	if reason != flagPercentage {
		t.Errorf("expected flagPercentage for 15/20 (75%%), got %v", reason)
	}
}

func TestFlagReasonString(t *testing.T) {
	tests := []struct {
		reason   flagReason
		expected string
	}{
		{notFlagged, ""},
		{flagAbsolute, "absolute threshold"},
		{flagPercentage, "percentage-of-templates threshold"},
	}
	for _, tt := range tests {
		got := tt.reason.String()
		if got != tt.expected {
			t.Errorf("flagReason(%d).String() = %q, expected %q", tt.reason, got, tt.expected)
		}
	}
}

func TestGetFlaggedHostsSortTieBreaker(t *testing.T) {
	tracker := NewTracker(2, nil)

	// Create multiple hosts with the same match count.
	tracker.RecordMatch("http://charlie.com", "CVE-2021-0001")
	tracker.RecordMatch("http://charlie.com", "CVE-2021-0002")
	tracker.RecordMatch("http://alpha.com", "CVE-2021-0001")
	tracker.RecordMatch("http://alpha.com", "CVE-2021-0002")
	tracker.RecordMatch("http://bravo.com", "CVE-2021-0001")
	tracker.RecordMatch("http://bravo.com", "CVE-2021-0002")

	flagged := tracker.GetFlaggedHosts()
	if len(flagged) != 3 {
		t.Fatalf("expected 3 flagged hosts, got %d", len(flagged))
	}

	// All have same match count, so should be sorted by host name ascending.
	expectedOrder := []string{"alpha.com", "bravo.com", "charlie.com"}
	for i, expected := range expectedOrder {
		if flagged[i].Host != expected {
			t.Errorf("flagged[%d].Host = %q, expected %q", i, flagged[i].Host, expected)
		}
	}
}

func TestNormalizeHostIPv6Safety(t *testing.T) {
	// Ensure IPv6 addresses ending in :80 are not corrupted.
	tests := []struct {
		input    string
		expected string
	}{
		// IPv6 address that ends with ::80 should NOT be stripped.
		{"2001:db8::80", "2001:db8::80"},
		// IPv6 with explicit port 80 in brackets should be stripped.
		{"http://[::1]:80/path", "::1"},
		// IPv6 with explicit port 443 in brackets should be stripped.
		{"http://[::1]:443/path", "::1"},
		// IPv6 with non-default port should be preserved.
		{"http://[::1]:8080/path", "[::1]:8080"},
		// IPv6 without port should unwrap brackets for consistency.
		{"http://[2001:db8::1]/path", "2001:db8::1"},
	}

	for _, tt := range tests {
		result := normalizeHost(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeHost(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com:80", "example.com"},
		{"https://example.com:443", "example.com"},
		{"http://example.com:8080", "example.com:8080"},
		{"http://EXAMPLE.COM", "example.com"},
		{"example.com", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"http://192.168.1.1:8080/path", "192.168.1.1:8080"},
		{"", ""},
	}

	for _, tt := range tests {
		result := normalizeHost(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeHost(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestStripDefaultPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:80", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com:8080"},
		{"example.com", "example.com"},
		// IPv6 without brackets — no valid host:port split, returned as-is.
		{"2001:db8::80", "2001:db8::80"},
		// IPv6 with brackets and default port.
		{"[::1]:80", "::1"},
		{"[::1]:443", "::1"},
		// IPv6 with brackets and non-default port.
		{"[::1]:8080", "[::1]:8080"},
		// Bare bracketed IPv6 without port — brackets should be unwrapped.
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
	}

	for _, tt := range tests {
		result := stripDefaultPort(tt.input)
		if result != tt.expected {
			t.Errorf("stripDefaultPort(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}
