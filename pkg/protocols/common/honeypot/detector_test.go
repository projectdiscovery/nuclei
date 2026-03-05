package honeypot

import (
	"testing"
)

func TestHoneypotDetector(t *testing.T) {
	detector := NewHoneypotDetector(10)

	// Test initial state
	if detector.IsHoneypot("example.com") {
		t.Error("New host should not be detected as honeypot")
	}

	// Add vulnerabilities
	for i := 0; i < 15; i++ {
		detector.AddVulnerability("example.com", "template-"+string(rune(i)))
	}

	// Should be detected as honeypot
	if !detector.IsHoneypot("example.com") {
		t.Error("Host with 15 vulns should be detected as honeypot")
	}

	// Check count
	count := detector.GetVulnerabilityCount("example.com")
	if count != 15 {
		t.Errorf("Expected 15 vulns, got %d", count)
	}
}

func TestHoneypotScore(t *testing.T) {
	detector := NewHoneypotDetector(10)

	tests := []struct {
		host       string
		vulnCount  int
		expectMin  int
		expectMax  int
	}{
		{"low.com", 5, 20, 30},
		{"medium.com", 15, 50, 65},
		{"high.com", 25, 90, 100},
	}

	for _, tt := range tests {
		for i := 0; i < tt.vulnCount; i++ {
			detector.AddVulnerability(tt.host, "template")
		}

		score := detector.GetHoneypotScore(tt.host)
		if score < tt.expectMin || score > tt.expectMax {
			t.Errorf("%s: expected score %d-%d, got %d", tt.host, tt.expectMin, tt.expectMax, score)
		}
	}
}

func TestReset(t *testing.T) {
	detector := NewHoneypotDetector(10)

	// Add data
	for i := 0; i < 15; i++ {
		detector.AddVulnerability("test.com", "template")
	}

	// Reset
	detector.Reset("test.com")

	// Should be cleared
	if detector.IsHoneypot("test.com") {
		t.Error("Reset host should not be detected as honeypot")
	}

	if detector.GetVulnerabilityCount("test.com") != 0 {
		t.Error("Reset host should have 0 vulns")
	}
}

func TestGetStats(t *testing.T) {
	detector := NewHoneypotDetector(10)

	// Add test data
	for i := 0; i < 5; i++ {
		detector.AddVulnerability("normal.com", "template")
	}
	for i := 0; i < 15; i++ {
		detector.AddVulnerability("honeypot.com", "template")
	}

	stats := detector.GetStats()

	if stats.TotalHosts != 2 {
		t.Errorf("Expected 2 hosts, got %d", stats.TotalHosts)
	}

	if stats.HoneypotHosts != 1 {
		t.Errorf("Expected 1 honeypot, got %d", stats.HoneypotHosts)
	}

	if stats.MaxVulnsOnHost != 15 {
		t.Errorf("Expected max 15, got %d", stats.MaxVulnsOnHost)
	}
}
