package honeypot

import (
	"fmt"
	"sync"
	"testing"
)

func TestDetectorBasicThreshold(t *testing.T) {
	d := New(3, false)

	if d.RecordMatch("http://example.com", "template-1") {
		t.Fatal("should not be flagged after 1 match")
	}
	if d.RecordMatch("http://example.com", "template-2") {
		t.Fatal("should not be flagged after 2 matches")
	}

	if !d.RecordMatch("http://example.com", "template-3") {
		t.Fatal("should be flagged after 3 matches")
	}
	if !d.IsFlagged("http://example.com") {
		t.Fatal("host should be flagged")
	}
}

func TestDetectorDuplicateTemplates(t *testing.T) {
	d := New(3, false)

	d.RecordMatch("host.com", "same-template")
	d.RecordMatch("host.com", "same-template")
	d.RecordMatch("host.com", "same-template")

	if d.IsFlagged("host.com") {
		t.Fatal("duplicate template should not increase count")
	}
	if d.MatchCount("host.com") != 1 {
		t.Fatalf("expected match count 1, got %d", d.MatchCount("host.com"))
	}
}

func TestDetectorHostIsolation(t *testing.T) {
	d := New(3, false)

	d.RecordMatch("host-a.com", "t1")
	d.RecordMatch("host-a.com", "t2")
	d.RecordMatch("host-b.com", "t1")
	d.RecordMatch("host-b.com", "t2")

	if d.IsFlagged("host-a.com") || d.IsFlagged("host-b.com") {
		t.Fatal("neither host should be flagged yet")
	}
}

func TestDetectorSuppression(t *testing.T) {
	d := New(2, false)
	d.RecordMatch("host.com", "t1")
	d.RecordMatch("host.com", "t2")
	if d.ShouldSuppress("host.com") {
		t.Fatal("should not suppress when suppress=false")
	}

	d2 := New(2, true)
	d2.RecordMatch("host.com", "t1")
	d2.RecordMatch("host.com", "t2")
	if !d2.ShouldSuppress("host.com") {
		t.Fatal("should suppress when suppress=true and host flagged")
	}

	if d2.ShouldSuppress("other.com") {
		t.Fatal("should not suppress unflagged host")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/path?q=1", "example.com"},
		{"https://example.com:8443/api", "example.com"},
		{"example.com:80", "example.com"},
		{"example.com", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"http://192.168.1.1:8080/", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"http://[::1]:8080/path", "::1"},
		{"http://user:pass@example.com/", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		got := normalizeHost(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeHost(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestDetectorConcurrency(t *testing.T) {
	d := New(50, false)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d.RecordMatch("target.com", fmt.Sprintf("template-%d", id))
		}(i)
	}
	wg.Wait()

	if !d.IsFlagged("target.com") {
		t.Fatal("should be flagged after 100 distinct templates (threshold 50)")
	}
}

func TestDetectorMatchCountAfterFlagged(t *testing.T) {
	d := New(2, false)
	d.RecordMatch("host.com", "t1")
	d.RecordMatch("host.com", "t2")

	if d.MatchCount("host.com") != -1 {
		t.Fatalf("expected -1 after flagging, got %d", d.MatchCount("host.com"))
	}
}

func TestDetectorSummary(t *testing.T) {
	d := New(2, false)

	if len(d.Summary()) != 0 {
		t.Fatal("summary should be empty initially")
	}

	d.RecordMatch("a.com", "t1")
	d.RecordMatch("a.com", "t2")
	d.RecordMatch("b.com", "t1")
	d.RecordMatch("b.com", "t2")

	summary := d.Summary()
	if len(summary) != 2 {
		t.Fatalf("expected 2 flagged hosts, got %d", len(summary))
	}
}

func TestDetectorEmptyHost(t *testing.T) {
	d := New(2, false)

	if d.RecordMatch("", "t1") {
		t.Fatal("empty host should return false")
	}
	if d.IsFlagged("") {
		t.Fatal("empty host should not be flagged")
	}
}

func TestDetectorSubsequentMatchesStillFlagged(t *testing.T) {
	d := New(2, true)
	d.RecordMatch("host.com", "t1")
	d.RecordMatch("host.com", "t2")

	if !d.RecordMatch("host.com", "t3") {
		t.Fatal("already flagged host should return true")
	}
	if !d.RecordMatch("host.com", "t4") {
		t.Fatal("already flagged host should return true")
	}
}
