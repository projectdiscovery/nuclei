package output

import (
	"fmt"
	"sync"
	"testing"
)

func TestHoneypotTracker_Basic(t *testing.T) {
	tracker := NewHoneypotTracker(3)

	// First two unique templates should not be suppressed
	if tracker.Check("http://example.com", "template-1") {
		t.Fatal("expected not suppressed for first match")
	}
	if tracker.Check("http://example.com", "template-2") {
		t.Fatal("expected not suppressed for second match")
	}

	// Duplicate template should not increment count
	if tracker.Check("http://example.com", "template-1") {
		t.Fatal("expected not suppressed for duplicate template")
	}

	// Third unique template should trigger honeypot detection
	if !tracker.Check("http://example.com", "template-3") {
		t.Fatal("expected suppressed at threshold")
	}

	// Subsequent checks should remain suppressed
	if !tracker.Check("http://example.com", "template-4") {
		t.Fatal("expected suppressed after flagged")
	}
}

func TestHoneypotTracker_DifferentHosts(t *testing.T) {
	tracker := NewHoneypotTracker(3)

	tracker.Check("http://host-a.com", "t1")
	tracker.Check("http://host-a.com", "t2")
	tracker.Check("http://host-b.com", "t1")

	// host-a reaches threshold
	if !tracker.Check("http://host-a.com", "t3") {
		t.Fatal("expected host-a suppressed")
	}

	// host-b only has 1 unique match, should not be affected
	if tracker.Check("http://host-b.com", "t2") {
		t.Fatal("expected host-b not suppressed yet")
	}
}

func TestHoneypotTracker_HostNormalization(t *testing.T) {
	tracker := NewHoneypotTracker(2)

	// Different formats of the same host should be normalized
	tracker.Check("http://example.com:8080/path", "t1")
	if !tracker.Check("https://example.com:443/other", "t2") {
		t.Fatal("expected same host after normalization")
	}
}

func TestHoneypotTracker_Concurrent(t *testing.T) {
	tracker := NewHoneypotTracker(100)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				tracker.Check("http://target.com", fmt.Sprintf("template-%d-%d", id, j))
			}
		}(i)
	}
	wg.Wait()

	// After 50*10=500 unique templates (well over threshold of 100), host should be flagged
	if !tracker.Check("http://target.com", "final") {
		t.Fatal("expected host flagged after concurrent writes")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"https://example.com:8443/path", "example.com"},
		{"http://[::1]:8080/test", "::1"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"example.com", "example.com"},
	}

	for _, tt := range tests {
		got := normalizeHost(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
