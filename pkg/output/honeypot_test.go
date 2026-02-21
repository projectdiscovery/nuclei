package output

import (
	"testing"
)

// TestNormalizeHostCandidate verifies host normalization from various input formats.
func TestNormalizeHostCandidate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"URL", "https://example.com:443/path", "example.com"},
		{"HostPort", "example.com:8080", "example.com"},
		{"HostOnly", "example.com", "example.com"},
		{"Empty", "", ""},
		{"IPv6WithPort", "[::1]:8080", "::1"},
		{"IPv6BracketOnly", "[::1]", "::1"},
		{"BareIPv4", "192.168.1.1", "192.168.1.1"},
		{"UppercaseScheme", "HTTPS://Example.COM", "example.com"},
		{"NonHTTPScheme", "tcp://host.local:4444", "host.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeHostCandidate(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHostCandidate(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNormalizeHoneypotHostIgnoresMatchedFallback verifies that event.Matched is NOT used as a fallback.
func TestNormalizeHoneypotHostIgnoresMatchedFallback(t *testing.T) {
	event := &ResultEvent{
		Host:    "",
		URL:     "",
		Matched: "arbitrary-content-not-a-host",
	}
	result := normalizeHoneypotHost(event)
	if result != "" {
		t.Errorf("normalizeHoneypotHost should ignore Matched fallback, got %q", result)
	}
}

// TestHoneypotDetectorThresholdBehavior verifies threshold-crossing logic:
// - Distinct templates increment count
// - Threshold-crossing event is NOT suppressed (visible)
// - Subsequent events ARE suppressed if suppress=true
func TestHoneypotDetectorThresholdBehavior(t *testing.T) {
	detector := newHoneypotDetector(3, true)

	events := []*ResultEvent{
		{TemplateID: "tpl-1", Host: "host-a"},
		{TemplateID: "tpl-2", Host: "host-a"},
		{TemplateID: "tpl-3", Host: "host-a"}, // crosses threshold
		{TemplateID: "tpl-4", Host: "host-a"}, // should be suppressed
	}

	// Event 1
	decision := detector.evaluate(events[0])
	if decision.suppress {
		t.Errorf("Event 1 should not be suppressed")
	}
	if decision.newlyFlagged {
		t.Errorf("Event 1 should not flag host")
	}

	// Event 2
	decision = detector.evaluate(events[1])
	if decision.suppress {
		t.Errorf("Event 2 should not be suppressed")
	}
	if decision.newlyFlagged {
		t.Errorf("Event 2 should not flag host")
	}

	// Event 3 (threshold crossing)
	decision = detector.evaluate(events[2])
	if decision.suppress {
		t.Errorf("Threshold-crossing event should NOT be suppressed")
	}
	if !decision.newlyFlagged {
		t.Errorf("Event 3 should flag host")
	}
	if decision.count != 3 {
		t.Errorf("Event 3 count = %d, want 3", decision.count)
	}

	// Event 4 (after flagging)
	decision = detector.evaluate(events[3])
	if !decision.suppress {
		t.Errorf("Event 4 should be suppressed")
	}
	if decision.newlyFlagged {
		t.Errorf("Event 4 should not newly flag (already flagged)")
	}
}

// TestHoneypotDetectorDeduplicatesSameTemplateID verifies same template-id on the same host
// is deduplicated (count stays at 1, host not flagged).
func TestHoneypotDetectorDeduplicatesSameTemplateID(t *testing.T) {
	detector := newHoneypotDetector(3, true)

	event := &ResultEvent{TemplateID: "tpl-1", Host: "host-a"}
	decision1 := detector.evaluate(event)
	decision2 := detector.evaluate(event) // duplicate

	if decision1.count != 1 {
		t.Errorf("First evaluation count = %d, want 1", decision1.count)
	}
	if decision2.count != 1 {
		t.Errorf("Second evaluation count = %d, want 1", decision2.count)
	}
	if decision1.newlyFlagged || decision2.newlyFlagged {
		t.Errorf("Host should not be flagged with duplicate template")
	}
}

// TestHoneypotDetectorPrunesHostMatchesAfterThreshold verifies memory is freed after flagging.
func TestHoneypotDetectorPrunesHostMatchesAfterThreshold(t *testing.T) {
	detector := newHoneypotDetector(2, true)

	detector.evaluate(&ResultEvent{TemplateID: "tpl-1", Host: "host-a"})
	detector.evaluate(&ResultEvent{TemplateID: "tpl-2", Host: "host-a"}) // crosses threshold

	detector.mu.Lock()
	defer detector.mu.Unlock()

	if _, exists := detector.hostMatches["host-a"]; exists {
		t.Errorf("hostMatches['host-a'] should be pruned after flagging")
	}
	if _, flagged := detector.flagged["host-a"]; !flagged {
		t.Errorf("host-a should remain in flagged map")
	}
}
