package honeypot

import (
	"sync"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com:8080/path", "example.com"},
		{"https://example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:8080", "[::1]"},
		{"http://[::1]:8080/path", "[::1]"},
		{"http://[2001:db8::1]:443", "[2001:db8::1]"},
		{"http://example.com?query=1", "example.com"},
		{"http://example.com#fragment", "example.com"},
		{"  example.com  ", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := normalizeHost(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDetectorAbsoluteThreshold(t *testing.T) {
	d := New(5, 0, 0, false)
	if d.Enabled() != true {
		t.Fatal("expected enabled")
	}

	// Should not flag before threshold
	for i := 0; i < 4; i++ {
		if d.RecordMatch("http://example.com", "tmpl-"+string(rune('A'+i))) {
			t.Fatalf("should not flag at match %d", i+1)
		}
	}

	// Should flag at threshold
	if !d.RecordMatch("http://example.com", "tmpl-E") {
		t.Fatal("should flag at match 5")
	}

	// Already flagged, should return true
	if !d.RecordMatch("http://example.com", "tmpl-F") {
		t.Fatal("should still be flagged")
	}

	if d.FlaggedCount() != 1 {
		t.Fatalf("expected 1 flagged, got %d", d.FlaggedCount())
	}
}

func TestDetectorDisabled(t *testing.T) {
	d := New(0, 0, 0, false)
	if d.Enabled() != false {
		t.Fatal("should be disabled")
	}
	if d.RecordMatch("http://example.com", "tmpl-A") {
		t.Fatal("should never flag when disabled")
	}
}

func TestDetectorMultipleHosts(t *testing.T) {
	d := New(3, 0, 0, false)

	// Host A: 3 matches → flagged
	d.RecordMatch("http://host-a.com", "t1")
	d.RecordMatch("http://host-a.com", "t2")
	if !d.RecordMatch("http://host-a.com", "t3") {
		t.Fatal("host-a should be flagged")
	}

	// Host B: 2 matches → not flagged
	d.RecordMatch("http://host-b.com", "t1")
	if d.RecordMatch("http://host-b.com", "t2") {
		t.Fatal("host-b should not be flagged")
	}

	if d.FlaggedCount() != 1 {
		t.Fatalf("expected 1 flagged, got %d", d.FlaggedCount())
	}
}

func TestDetectorPercentageThreshold(t *testing.T) {
	// 10 total templates, 50% threshold → flag at 5 matches
	d := New(0, 10, 50, false)
	if d.Enabled() != true {
		t.Fatal("expected enabled")
	}

	for i := 0; i < 4; i++ {
		if d.RecordMatch("http://example.com", "t-"+string(rune('A'+i))) {
			t.Fatalf("should not flag at %d matches", i+1)
		}
	}

	if !d.RecordMatch("http://example.com", "t-E") {
		t.Fatal("should flag at 50% (5/10)")
	}
}

func TestDetectorHostGrouping(t *testing.T) {
	d := New(3, 0, 0, false)

	// Different schemes/ports should group to same host
	d.RecordMatch("http://example.com:80", "t1")
	d.RecordMatch("https://example.com:443/path", "t2")

	if d.IsFlagged("http://example.com") {
		t.Fatal("should not be flagged yet")
	}

	// Third unique template hits threshold
	d.RecordMatch("http://example.com:8080/api", "t3")
	if !d.IsFlagged("http://example.com") {
		t.Fatal("should be flagged after 3 unique templates")
	}

	// Different port should also be flagged (same host)
	if !d.IsFlagged("https://example.com:443") {
		t.Fatal("should be flagged across schemes")
	}
}

func TestDetectorDuplicateTemplateIDs(t *testing.T) {
	d := New(3, 0, 0, false)

	// Same template should not count twice
	d.RecordMatch("http://example.com", "t1")
	d.RecordMatch("http://example.com", "t1")
	d.RecordMatch("http://example.com", "t2")

	if d.IsFlagged("http://example.com") {
		t.Fatal("2 unique templates should not reach threshold of 3")
	}
}

func TestDetectorIsFlagged(t *testing.T) {
	d := New(2, 0, 0, false)

	if d.IsFlagged("http://example.com") {
		t.Fatal("should not be flagged initially")
	}

	d.RecordMatch("http://example.com", "t1")
	d.RecordMatch("http://example.com", "t2")

	if !d.IsFlagged("http://example.com") {
		t.Fatal("should be flagged")
	}
}

func TestDetectorConcurrency(t *testing.T) {
	d := New(100, 0, 0, false)
	var wg sync.WaitGroup

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d.RecordMatch("http://example.com", "t-"+string(rune(id%200)))
		}(i)
	}
	wg.Wait()

	// Should have exactly 200 unique templates
	if !d.IsFlagged("http://example.com") {
		t.Fatal("should be flagged with 200 unique templates")
	}
	if d.FlaggedCount() != 1 {
		t.Fatalf("expected 1 flagged host, got %d", d.FlaggedCount())
	}
}

func TestCheckSignature(t *testing.T) {
	tests := []struct {
		body    string
		wantSig string
		wantOk  bool
	}{
		{"SSH-2.0-Cowrie", "cowrie", true},
		{"Normal server response", "", false},
		{"Dionaea honeypot active", "dionaea", true},
		{"Glastopf sensor", "glastopf", true},
		{"CONPOT", "conpot", true},
	}

	for _, tt := range tests {
		sig, ok := CheckSignature(tt.body)
		if ok != tt.wantOk || sig != tt.wantSig {
			t.Errorf("CheckSignature(%q) = (%q, %v), want (%q, %v)", tt.body, sig, ok, tt.wantSig, tt.wantOk)
		}
	}
}

func TestHostURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com:8080/path", "example.com:8080"},
		{"https://example.com", "example.com"},
		{"http://192.168.1.1:443/api", "192.168.1.1:443"},
	}

	for _, tt := range tests {
		got := HostURL(tt.input)
		if got != tt.expected {
			t.Errorf("HostURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
