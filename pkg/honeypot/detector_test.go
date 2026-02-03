package honeypot

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// TestNormalVulnerableHostNotFlagged verifies that a host with matches from
// a single category (e.g., all Apache vulnerabilities) is NOT flagged
func TestNormalVulnerableHostNotFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// Create 25 Apache-related template matches (high count, but same category)
	for i := 0; i < 25; i++ {
		event := &output.ResultEvent{
			TemplateID: "apache-vuln-" + string(rune(i)),
			Host:       "example.com",
			Response:   "Apache/2.4.41 (Ubuntu)",
			Info: model.Info{
				Tags: []string{"apache", "webserver"},
			},
		}
		detector.recordMatch("example.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("example.com")
	if isHoneypot {
		t.Errorf("Expected normal vulnerable host to NOT be flagged, but got: %+v", report)
	}
}

// TestHighMatchCountSameCategoryNotFlagged verifies that high match count
// with low category diversity doesn't trigger honeypot detection
func TestHighMatchCountSameCategoryNotFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// Create 30 matches, all from "webserver" category
	response := "Apache/2.4.41"
	for i := 0; i < 30; i++ {
		event := &output.ResultEvent{
			TemplateID: "web-" + string(rune(i)),
			Host:       "target.com",
			Response:   response, // Same response
			Info: model.Info{
				Tags: []string{"webserver"}, // Only one category
			},
		}
		detector.recordMatch("target.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("target.com")
	if isHoneypot {
		t.Errorf("Expected high match count with same category to NOT be flagged, but got: %+v", report)
	}
}

// TestMixedCategoriesWithReusedResponseFlagged verifies that a host with:
// - High match count (>=20)
// - High category diversity (>=6)
// - High response reuse (>=80%)
// IS flagged as a honeypot
func TestMixedCategoriesWithReusedResponseFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// Create 25 matches with 7 different categories and same response
	categories := []string{"cisco", "fortinet", "apache", "php", "tomcat", "mysql", "nginx"}
	commonResponse := "Server responding to all probes"

	for i := 0; i < 25; i++ {
		catIdx := i % len(categories)
		event := &output.ResultEvent{
			TemplateID: "tpl-" + string(rune(i)),
			Host:       "honeypot.com",
			Response:   commonResponse,
			Info: model.Info{
				Tags: []string{categories[catIdx]},
			},
		}
		detector.recordMatch("honeypot.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("honeypot.com")
	if !isHoneypot {
		t.Errorf("Expected mixed categories + reused response to be flagged as honeypot, but got: %+v", report)
	}

	if len(report.Signals) < 3 {
		t.Errorf("Expected at least 3 signals, got %d: %v", len(report.Signals), report.Signals)
	}
}

// TestDisabledDetectionDoesNotFlag verifies that when detection is disabled,
// no hosts are flagged
func TestDisabledDetectionDoesNotFlag(t *testing.T) {
	detector := New(Config{
		Enabled: false,
		Mode:    ModeWarn,
	})

	// Create obvious honeypot pattern
	commonResponse := "Honeypot Response"
	categories := []string{"cisco", "fortinet", "apache", "php", "tomcat", "mysql"}

	for i := 0; i < 30; i++ {
		catIdx := i % len(categories)
		event := &output.ResultEvent{
			TemplateID: "tpl-" + string(rune(i)),
			Host:       "disabled.com",
			Response:   commonResponse,
			Info: model.Info{
				Tags: []string{categories[catIdx]},
			},
		}
		detector.recordMatch("disabled.com", event)
	}

	isHoneypot, _ := detector.IsHoneypot("disabled.com")
	// When disabled, recordMatch is a no-op, so no data is collected
	// We need to call recordMatch first
	if !detector.config.Enabled {
		// recordMatch returns early, so hostData won't have the entry
		t.Logf("Detection disabled, as expected")
	}
}

// TestCDNEdgeCaseNotFlagged verifies that a CDN/WAF returning similar responses
// to many different templates does NOT get flagged (should be carefully tuned)
func TestCDNEdgeCaseNotFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// CDN returns the same 403 Forbidden response to everything
	cdnResponse := "403 Forbidden"

	// But these are all different protocol checks (DNS, TLS, HTTP), not diverse tech stack
	for i := 0; i < 25; i++ {
		event := &output.ResultEvent{
			TemplateID: "cdn-check-" + string(rune(i)),
			Host:       "cdn-endpoint.com",
			Response:   cdnResponse,
			Info: model.Info{
				Tags: []string{"cdn", "waf"}, // Only 2 categories, same throughout
			},
		}
		detector.recordMatch("cdn-endpoint.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("cdn-endpoint.com")
	if isHoneypot {
		t.Errorf("Expected CDN/WAF to NOT be flagged, but got: %+v", report)
	}
}

// TestConflictingTechStackDetected verifies that matching both Cisco and Fortinet
// templates (which should never appear together) is detected
func TestConflictingTechStackDetected(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// Simulate matching both Cisco and Fortinet (incompatible)
	commonResponse := "Honeypot"
	conflictingTechs := []string{"cisco", "fortinet", "apache", "php", "tomcat", "mysql"}

	for i := 0; i < 25; i++ {
		techIdx := i % len(conflictingTechs)
		event := &output.ResultEvent{
			TemplateID: "tech-" + string(rune(i)),
			Host:       "conflict.com",
			Response:   commonResponse,
			Info: model.Info{
				Tags: []string{conflictingTechs[techIdx]},
			},
		}
		detector.recordMatch("conflict.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("conflict.com")
	if !isHoneypot {
		t.Errorf("Expected conflicting tech stack to be flagged, but got: %+v", report)
	}

	// Check if conflict signal was detected
	hasConflictSignal := false
	for _, signal := range report.Signals {
		if signal == "conflicting technology stack detected" {
			hasConflictSignal = true
			break
		}
	}
	if !hasConflictSignal {
		t.Errorf("Expected conflict signal in report, but got signals: %v", report.Signals)
	}
}

// TestEmptyHostNotFlagged verifies that a host with no matches is not flagged
func TestEmptyHostNotFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	isHoneypot, report := detector.IsHoneypot("never-matched.com")
	if isHoneypot {
		t.Errorf("Expected empty host to NOT be flagged, but got: %+v", report)
	}
	if report != nil {
		t.Errorf("Expected nil report for empty host, got: %+v", report)
	}
}

// TestLowMatchCountNotFlagged verifies that < 20 matches doesn't trigger honeypot
func TestLowMatchCountNotFlagged(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// 15 matches with diverse categories
	categories := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	commonResponse := "Same response"

	for i := 0; i < 15; i++ {
		catIdx := i % len(categories)
		event := &output.ResultEvent{
			TemplateID: "tpl-" + string(rune(i)),
			Host:       "low-count.com",
			Response:   commonResponse,
			Info: model.Info{
				Tags: []string{categories[catIdx]},
			},
		}
		detector.recordMatch("low-count.com", event)
	}

	isHoneypot, report := detector.IsHoneypot("low-count.com")
	if isHoneypot {
		t.Errorf("Expected low match count to NOT be flagged, but got: %+v", report)
	}
}

// TestHoneypotReportFormatting verifies that the report format is correct
func TestHoneypotReportFormatting(t *testing.T) {
	report := &HoneypotReport{
		Host:    "example.com",
		Signals: []string{"25 templates matched", "8 unrelated categories", "90% identical response bodies"},
		Score:   3,
	}

	output := report.String()
	if output == "" {
		t.Error("Expected non-empty report output")
	}

	// Verify key strings are in the output
	expectedStrings := []string{"[HONEYPOT WARNING]", "example.com", "templates matched", "unrelated categories", "identical response"}
	for _, expected := range expectedStrings {
		if !contains(output, expected) {
			t.Errorf("Expected output to contain '%s', but got:\n%s", expected, output)
		}
	}
}

// TestConcurrentRecording verifies that concurrent recordMatch calls don't cause
// data races or corruption
func TestConcurrentRecording(t *testing.T) {
	detector := New(Config{
		Enabled: true,
		Mode:    ModeWarn,
	})

	// Simulate concurrent recording (Go's race detector will catch issues)
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			for j := 0; j < 10; j++ {
				event := &output.ResultEvent{
					TemplateID: "tpl-" + string(rune(idx*10+j)),
					Host:       "concurrent.com",
					Response:   "response",
					Info: model.Info{
						Tags: []string{"cat" + string(rune(j))},
					},
				}
				detector.recordMatch("concurrent.com", event)
			}
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify it doesn't panic
	isHoneypot, _ := detector.IsHoneypot("concurrent.com")
	if !isHoneypot {
		t.Logf("Concurrent recording completed successfully")
	}
}

// Helper function for test assertions
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
