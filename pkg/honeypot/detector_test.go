package honeypot

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestNewDetector verifies that a new detector is properly initialized.
func TestNewDetector(t *testing.T) {
	d := New(10)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if !d.Enabled() {
		t.Fatal("expected detector to be enabled with threshold 10")
	}
}

// TestDisabledDetector verifies that a zero-threshold detector is inactive.
func TestDisabledDetector(t *testing.T) {
	d := New(0)
	if d.Enabled() {
		t.Fatal("expected detector to be disabled with threshold 0")
	}
	if d.Record("example.com", "cve-2021-1234") {
		t.Fatal("disabled detector should never flag")
	}
	if d.IsFlagged("example.com") {
		t.Fatal("disabled detector should never flag")
	}
	if d.MatchCount("example.com") != 0 {
		t.Fatal("disabled detector should return 0 match count")
	}
}

// TestNilDetector verifies that nil receiver methods are safe.
func TestNilDetector(t *testing.T) {
	var d *Detector
	if d.Enabled() {
		t.Fatal("nil detector should not be enabled")
	}
	if d.Record("host", "tmpl") {
		t.Fatal("nil detector should not flag")
	}
	if d.IsFlagged("host") {
		t.Fatal("nil detector should not flag")
	}
	if d.MatchCount("host") != 0 {
		t.Fatal("nil detector should return 0")
	}
	if hosts := d.FlaggedHosts(); hosts != nil {
		t.Fatal("nil detector should return nil flagged hosts")
	}
	if summary := d.Summary(); summary != "" {
		t.Fatal("nil detector should return empty summary")
	}
}

// TestThresholdTriggering verifies that a host is flagged when it
// exceeds the configured threshold (strictly greater than).
func TestThresholdTriggering(t *testing.T) {
	d := New(3)

	// First three matches should not trigger (at threshold, not exceeding)
	if d.Record("example.com", "tmpl-1") {
		t.Fatal("should not be flagged after 1 match")
	}
	if d.Record("example.com", "tmpl-2") {
		t.Fatal("should not be flagged after 2 matches")
	}
	if d.Record("example.com", "tmpl-3") {
		t.Fatal("should not be flagged at threshold (3 matches)")
	}
	if d.IsFlagged("example.com") {
		t.Fatal("should not be flagged at threshold")
	}

	// Fourth match exceeds threshold -- should trigger
	if !d.Record("example.com", "tmpl-4") {
		t.Fatal("should be flagged after exceeding threshold (4 > 3)")
	}
	if !d.IsFlagged("example.com") {
		t.Fatal("should be flagged after exceeding threshold")
	}
	if d.MatchCount("example.com") != 4 {
		t.Fatalf("expected 4 matches, got %d", d.MatchCount("example.com"))
	}
}

// TestDuplicateTemplatesNotCounted verifies that duplicate template
// matches for the same host are deduplicated.
func TestDuplicateTemplatesNotCounted(t *testing.T) {
	d := New(3)

	// Record the same template multiple times
	d.Record("example.com", "tmpl-1")
	d.Record("example.com", "tmpl-1")
	d.Record("example.com", "tmpl-1")

	if d.IsFlagged("example.com") {
		t.Fatal("duplicate templates should not increase count")
	}
	if d.MatchCount("example.com") != 1 {
		t.Fatalf("expected 1 unique match, got %d", d.MatchCount("example.com"))
	}
}

// TestMultiHostIsolation verifies that match counts are tracked
// independently per host.
func TestMultiHostIsolation(t *testing.T) {
	d := New(2)

	d.Record("host-a.com", "tmpl-1")
	d.Record("host-b.com", "tmpl-1")

	if d.IsFlagged("host-a.com") || d.IsFlagged("host-b.com") {
		t.Fatal("neither host should be flagged with only 1 match each")
	}

	d.Record("host-a.com", "tmpl-2")
	if d.IsFlagged("host-a.com") {
		t.Fatal("host-a should not be flagged at threshold (2 matches = threshold)")
	}

	// Exceeding threshold triggers flagging
	d.Record("host-a.com", "tmpl-3")
	if !d.IsFlagged("host-a.com") {
		t.Fatal("host-a should be flagged after exceeding threshold (3 > 2)")
	}
	if d.IsFlagged("host-b.com") {
		t.Fatal("host-b should not be flagged")
	}
}

// TestHostNormalizationURLs verifies that hosts are normalized
// consistently from different URL formats.
func TestHostNormalizationURLs(t *testing.T) {
	d := New(2)

	// These should all normalize to the same host
	d.Record("http://example.com/path", "tmpl-1")
	d.Record("https://example.com:443/other", "tmpl-2")
	d.Record("example.com", "tmpl-3")

	if !d.IsFlagged("example.com") {
		t.Fatal("normalized host should be flagged after exceeding threshold")
	}
}

// TestHostNormalizationNonStandardPort verifies that non-standard
// ports are preserved in normalization.
func TestHostNormalizationNonStandardPort(t *testing.T) {
	d := New(2)

	d.Record("http://example.com:8080/path", "tmpl-1")
	d.Record("http://example.com:8080/other", "tmpl-2")
	d.Record("http://example.com:8080/third", "tmpl-3")

	if !d.IsFlagged("example.com:8080") {
		t.Fatal("host with non-standard port should be flagged after exceeding threshold")
	}
	// Standard port host should NOT be flagged
	if d.IsFlagged("example.com") {
		t.Fatal("standard port host should not be flagged by non-standard port matches")
	}
}

// TestHostNormalizationIPv6 verifies that IPv6 addresses are handled
// correctly.
func TestHostNormalizationIPv6(t *testing.T) {
	d := New(2)

	d.Record("http://[::1]:8080/test", "tmpl-1")
	d.Record("[::1]:8080", "tmpl-2")
	d.Record("http://[::1]:8080/other", "tmpl-3")

	if !d.IsFlagged("[::1]:8080") {
		t.Fatal("IPv6 host should be flagged after exceeding threshold")
	}
}

// TestHostNormalizationCaseInsensitive verifies that host matching
// is case-insensitive.
func TestHostNormalizationCaseInsensitive(t *testing.T) {
	d := New(2)

	d.Record("EXAMPLE.COM", "tmpl-1")
	d.Record("example.com", "tmpl-2")
	d.Record("Example.Com", "tmpl-3")

	if !d.IsFlagged("Example.Com") {
		t.Fatal("host matching should be case-insensitive")
	}
}

// TestEmptyHostIgnored verifies that empty hosts are rejected.
func TestEmptyHostIgnored(t *testing.T) {
	d := New(1)

	if d.Record("", "tmpl-1") {
		t.Fatal("empty host should not be flagged")
	}
	if d.Record("   ", "tmpl-1") {
		t.Fatal("whitespace host should not be flagged")
	}
}

// TestFlaggedHosts verifies the FlaggedHosts method returns correct data.
func TestFlaggedHosts(t *testing.T) {
	d := New(2)

	d.Record("host-a.com", "tmpl-1")
	d.Record("host-a.com", "tmpl-2")
	d.Record("host-a.com", "tmpl-3") // exceeds threshold
	d.Record("host-b.com", "tmpl-1")

	flagged := d.FlaggedHosts()
	if len(flagged) != 1 {
		t.Fatalf("expected 1 flagged host, got %d", len(flagged))
	}
	if count, ok := flagged["host-a.com"]; !ok || count != 3 {
		t.Fatalf("expected host-a.com with 3 matches, got %v", flagged)
	}
}

// TestSummary verifies the Summary method returns a non-empty string
// when hosts are flagged.
func TestSummary(t *testing.T) {
	d := New(1)

	if summary := d.Summary(); summary != "" {
		t.Fatal("expected empty summary with no flagged hosts")
	}

	d.Record("example.com", "tmpl-1")
	d.Record("example.com", "tmpl-2") // exceeds threshold of 1
	summary := d.Summary()
	if summary == "" {
		t.Fatal("expected non-empty summary after flagging")
	}
	if !strings.Contains(summary, "example.com") {
		t.Fatal("summary should contain the flagged host")
	}
	if !strings.Contains(summary, "1 host(s)") {
		t.Fatal("summary should contain the count")
	}
}

// TestConcurrentAccess verifies that the detector is safe for
// concurrent use by multiple goroutines.
func TestConcurrentAccess(t *testing.T) {
	d := New(50)
	var wg sync.WaitGroup

	// Spawn 100 goroutines each recording different templates
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			host := "target.com"
			tmpl := fmt.Sprintf("tmpl-%d", idx)
			d.Record(host, tmpl)
		}(i)
	}

	wg.Wait()

	count := d.MatchCount("target.com")
	if count != 100 {
		t.Fatalf("expected 100 unique matches after concurrent writes, got %d", count)
	}
	if !d.IsFlagged("target.com") {
		t.Fatal("host should be flagged after 100 matches with threshold 50")
	}
}

// TestRecordReturnsTrueAfterFlagging verifies that Record keeps
// returning true after initial flagging.
func TestRecordReturnsTrueAfterFlagging(t *testing.T) {
	d := New(1)

	if d.Record("host.com", "tmpl-1") {
		t.Fatal("should not be flagged at threshold (1 match = threshold 1)")
	}
	// Second record exceeds threshold -- should flag
	if !d.Record("host.com", "tmpl-2") {
		t.Fatal("should be flagged after exceeding threshold")
	}
	// Additional records should still return true
	if !d.Record("host.com", "tmpl-3") {
		t.Fatal("should remain flagged")
	}
}

// TestNormalizeHostTrailingColon verifies trailing colon handling.
func TestNormalizeHostTrailingColon(t *testing.T) {
	d := New(2)

	d.Record("example.com:", "tmpl-1")
	d.Record("example.com", "tmpl-2")
	d.Record("example.com:", "tmpl-3") // exceeds threshold

	if !d.IsFlagged("example.com") {
		t.Fatal("trailing colon should normalize to same host")
	}
}

// TestNormalizeHostBareDefaultPort verifies that default ports are
// stripped from bare host:port inputs (not just URLs).
func TestNormalizeHostBareDefaultPort(t *testing.T) {
	d := New(2)

	d.Record("example.com:443", "tmpl-1")
	d.Record("example.com", "tmpl-2")
	d.Record("example.com:80", "tmpl-3") // exceeds threshold

	if !d.IsFlagged("example.com") {
		t.Fatal("bare host:443 and host:80 should normalize to host without port")
	}
	if d.MatchCount("example.com") != 3 {
		t.Fatalf("expected 3 matches, got %d", d.MatchCount("example.com"))
	}
}

// TestSummaryDeterministic verifies that Summary output is sorted.
func TestSummaryDeterministic(t *testing.T) {
	d := New(1)

	// Flag multiple hosts
	d.Record("zebra.com", "tmpl-1")
	d.Record("zebra.com", "tmpl-2")
	d.Record("alpha.com", "tmpl-1")
	d.Record("alpha.com", "tmpl-2")
	d.Record("middle.com", "tmpl-1")
	d.Record("middle.com", "tmpl-2")

	summary := d.Summary()
	alphaIdx := strings.Index(summary, "alpha.com")
	middleIdx := strings.Index(summary, "middle.com")
	zebraIdx := strings.Index(summary, "zebra.com")

	if alphaIdx == -1 || middleIdx == -1 || zebraIdx == -1 {
		t.Fatal("summary should contain all flagged hosts")
	}
	if !(alphaIdx < middleIdx && middleIdx < zebraIdx) {
		t.Fatal("summary hosts should be sorted alphabetically")
	}
}

