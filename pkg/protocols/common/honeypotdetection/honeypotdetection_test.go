package honeypotdetection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCache(t *testing.T) {
	cache := New(0) // should use default
	assert.Equal(t, DefaultThreshold, cache.threshold)

	cache = New(75)
	assert.Equal(t, 75, cache.threshold)
}

func TestNormalizeHost(t *testing.T) {
	cache := New(50)

	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com:443"},
		{"http://example.com", "example.com:80"},
		{"https://example.com:8443", "example.com:8443"},
		{"example.com:80", "example.com:80"},
		{"example.com", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1:8080"},
		{"", ""},
	}

	for _, tt := range tests {
		result := cache.normalizeHost(tt.input)
		assert.Equal(t, tt.expected, result, "normalizeHost(%q)", tt.input)
	}
}

func TestRecordMatch(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	// Record a match
	cache.RecordMatch("example.com:80", "CVE-2021-1234", "")

	matches, total, ratio := cache.GetStats("example.com:80")
	assert.Equal(t, 1, matches)
	assert.Equal(t, 100, total)
	assert.InDelta(t, 1.0, ratio, 0.1)
}

func TestDuplicateTemplateMatch(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	// Record the same template twice for the same host
	cache.RecordMatch("example.com:80", "CVE-2021-1234", "")
	cache.RecordMatch("example.com:80", "CVE-2021-1234", "")

	matches, _, _ := cache.GetStats("example.com:80")
	assert.Equal(t, 1, matches, "duplicate template matches should not be counted")
}

func TestHoneypotDetection(t *testing.T) {
	cache := New(50) // 50% threshold
	cache.SetTotalTemplates(20)

	host := "honeypot.example.com:80"

	// Record matches until we exceed threshold
	for i := 0; i < 11; i++ { // 11/20 = 55% > 50%
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	assert.True(t, cache.IsHoneypot(host), "host should be flagged as honeypot")
}

func TestNotHoneypot(t *testing.T) {
	cache := New(50) // 50% threshold
	cache.SetTotalTemplates(20)

	host := "legitimate.example.com:80"

	// Record a few matches, but under threshold
	for i := 0; i < 5; i++ { // 5/20 = 25% < 50%
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	assert.False(t, cache.IsHoneypot(host), "host should not be flagged as honeypot")
}

func TestMinTemplatesForDetection(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(5) // Below MinTemplatesForDetection

	host := "example.com:80"

	// Even with 100% match rate, shouldn't flag because not enough templates
	for i := 0; i < 5; i++ {
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	assert.False(t, cache.IsHoneypot(host), "should not flag with too few templates")
}

func TestGetAllSuspectedHoneypots(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(20)

	hosts := []string{"honeypot1.com:80", "honeypot2.com:80", "legit.com:80"}

	// Make first two hosts honeypots
	for _, host := range hosts[:2] {
		for i := 0; i < 15; i++ { // 15/20 = 75%
			cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
		}
	}

	// Third host is legitimate
	for i := 0; i < 3; i++ { // 3/20 = 15%
		cache.RecordMatch(hosts[2], "template-"+string(rune('a'+i)), "")
	}

	suspected := cache.GetAllSuspectedHoneypots()
	assert.Len(t, suspected, 2, "should have 2 suspected honeypots")
}

func TestConcurrentAccess(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	// Simulate concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				cache.RecordMatch("concurrent.example.com:80", "template-"+string(rune(id*100+j)), "")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	matches, _, _ := cache.GetStats("concurrent.example.com:80")
	assert.Equal(t, 1000, matches, "all matches should be recorded")
}

func TestURLHost(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	// Record match with URL instead of host
	cache.RecordMatch("", "CVE-2021-1234", "https://example.com/path/to/resource")

	matches, _, _ := cache.GetStats("https://example.com")
	assert.Equal(t, 1, matches)
}

// TestThresholdEdgeCases tests exact threshold boundary conditions
func TestThresholdEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		threshold       int
		totalTemplates  int
		matches         int
		expectHoneypot  bool
	}{
		{
			name:            "exactly at 49% with 50% threshold",
			threshold:       50,
			totalTemplates:  100,
			matches:         49,
			expectHoneypot:  false,
		},
		{
			name:            "exactly at 50% with 50% threshold",
			threshold:       50,
			totalTemplates:  100,
			matches:         50,
			expectHoneypot:  true,
		},
		{
			name:            "exactly at 51% with 50% threshold",
			threshold:       50,
			totalTemplates:  100,
			matches:         51,
			expectHoneypot:  true,
		},
		{
			name:            "at threshold with odd numbers (14/30 = 46.67%)",
			threshold:       50,
			totalTemplates:  30,
			matches:         14,
			expectHoneypot:  false,
		},
		{
			name:            "at threshold with odd numbers (15/30 = 50%)",
			threshold:       50,
			totalTemplates:  30,
			matches:         15,
			expectHoneypot:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := New(tt.threshold)
			cache.SetTotalTemplates(tt.totalTemplates)

			host := "threshold-test.example.com:80"

			// Record the specified number of unique matches
			for i := 0; i < tt.matches; i++ {
				cache.RecordMatch(host, "template-"+string(rune('A'+i/26))+string(rune('a'+i%26)), "")
			}

			assert.Equal(t, tt.expectHoneypot, cache.IsHoneypot(host),
				"expected honeypot=%v for %d/%d templates (%.2f%%)",
				tt.expectHoneypot, tt.matches, tt.totalTemplates,
				float64(tt.matches)/float64(tt.totalTemplates)*100)
		})
	}
}

// TestZeroTemplates tests behavior with 0 total templates
func TestZeroTemplates(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(0)

	host := "zero-templates.example.com:80"
	cache.RecordMatch(host, "CVE-2021-1234", "")

	// Should not panic, should not flag as honeypot (division by zero guard)
	assert.False(t, cache.IsHoneypot(host), "should not flag with 0 total templates")

	matches, total, ratio := cache.GetStats(host)
	assert.Equal(t, 1, matches)
	assert.Equal(t, 0, total)
	assert.Equal(t, 0.0, ratio)
}

// TestNineTemplates tests behavior with 9 templates (below MinTemplatesForDetection)
func TestNineTemplates(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(9) // Below MinTemplatesForDetection (10)

	host := "nine-templates.example.com:80"

	// Match all 9 templates (100%)
	for i := 0; i < 9; i++ {
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	// Should not flag because below minimum
	assert.False(t, cache.IsHoneypot(host), "should not flag with only 9 templates (below minimum)")
}

// TestTenTemplates tests behavior with exactly 10 templates (at MinTemplatesForDetection)
func TestTenTemplates(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(10) // Exactly MinTemplatesForDetection

	host := "ten-templates.example.com:80"

	// Match 6 templates (60% > 50%)
	for i := 0; i < 6; i++ {
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	// Should flag because we're at minimum templates and above threshold
	assert.True(t, cache.IsHoneypot(host), "should flag with 10 templates when above threshold")
}

// TestConcurrentMixedAccess tests concurrent access to multiple methods
func TestConcurrentMixedAccess(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(1000)

	hosts := []string{
		"concurrent1.example.com:80",
		"concurrent2.example.com:80",
		"concurrent3.example.com:80",
	}

	done := make(chan bool)
	errChan := make(chan error, 100)

	// Writer goroutines - RecordMatch
	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				for _, host := range hosts {
					cache.RecordMatch(host, "template-"+string(rune(id*1000+j)), "")
				}
			}
		}(i)
	}

	// Reader goroutines - GetStats and IsHoneypot
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				for _, host := range hosts {
					cache.GetStats(host)
					cache.IsHoneypot(host)
				}
			}
		}()
	}

	// GetAllSuspectedHoneypots goroutines
	for i := 0; i < 3; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				cache.GetAllSuspectedHoneypots()
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 13; i++ {
		<-done
	}

	close(errChan)
	for err := range errChan {
		t.Errorf("concurrent access error: %v", err)
	}

	// Verify data integrity - should have recorded matches
	for _, host := range hosts {
		matches, _, _ := cache.GetStats(host)
		assert.Greater(t, matches, 0, "should have recorded matches for %s", host)
	}
}

// TestHostNormalizationComprehensive tests various host input formats
func TestHostNormalizationComprehensive(t *testing.T) {
	cache := New(50)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// HTTP/HTTPS URLs
		{"https with default port", "https://example.com", "example.com:443"},
		{"http with default port", "http://example.com", "example.com:80"},
		{"https with custom port", "https://example.com:8443", "example.com:8443"},
		{"http with custom port", "http://example.com:8080", "example.com:8080"},
		{"https with path", "https://example.com/path/to/resource", "example.com:443"},
		{"http with query", "http://example.com:8080?query=1", "example.com:8080"},

		// Host:port format
		{"host:port standard", "example.com:80", "example.com:80"},
		{"host:port custom", "example.com:9999", "example.com:9999"},
		{"ip:port", "192.168.1.1:8080", "192.168.1.1:8080"},

		// Bare hostnames/IPs
		{"bare hostname", "example.com", "example.com"},
		{"bare ip", "192.168.1.1", "192.168.1.1"},

		// IPv6 addresses
		{"ipv6 with port", "[::1]:8080", "[::1]:8080"},
		{"ipv6 https url", "https://[::1]:8443/path", "[::1]:8443"},
		{"ipv6 http url", "http://[2001:db8::1]/", "[2001:db8::1]:80"},
		{"bracketed ipv6 without port", "[::1]", "::1"},

		// Edge cases
		{"empty string", "", ""},
		{"ftp scheme", "ftp://ftp.example.com", "ftp.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cache.normalizeHost(tt.input)
			assert.Equal(t, tt.expected, result, "normalizeHost(%q)", tt.input)
		})
	}
}

// TestDuplicateTemplateFilteringComprehensive tests that duplicate templates are properly filtered
func TestDuplicateTemplateFilteringComprehensive(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	host := "duplicate-test.example.com:80"

	// Record same template multiple times in different ways
	templates := []string{"CVE-2021-1234", "CVE-2021-5678"}

	for _, tmpl := range templates {
		// Record each template 10 times
		for i := 0; i < 10; i++ {
			cache.RecordMatch(host, tmpl, "")
		}
	}

	matches, _, _ := cache.GetStats(host)
	assert.Equal(t, 2, matches, "should only count 2 unique templates despite 20 RecordMatch calls")
}

// TestHostNormalizationConsistency ensures the same host from different formats is treated as one
func TestHostNormalizationConsistency(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	// All these should normalize to the same host
	inputs := []string{
		"https://example.com",
		"https://example.com/",
		"https://example.com/path",
		"https://example.com:443",
		"https://example.com:443/path",
		"example.com:443",
	}

	// Record one match from each input format with a unique template
	for i, input := range inputs {
		cache.RecordMatch("", "template-"+string(rune('a'+i)), input)
	}

	// Check that all matches are aggregated under the same normalized host
	matches, _, _ := cache.GetStats("https://example.com")
	assert.Equal(t, len(inputs), matches, "all inputs should normalize to same host")
}

// TestRecordScanWithoutMatch tests that RecordScan properly tracks scans
func TestRecordScanWithoutMatch(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(100)

	host := "scan-test.example.com:80"

	// Record scans without matches
	for i := 0; i < 20; i++ {
		cache.RecordScan(host)
	}

	// Record some matches
	for i := 0; i < 5; i++ {
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	matches, total, ratio := cache.GetStats(host)
	assert.Equal(t, 5, matches)
	assert.Equal(t, 20, total) // Should use templatesScanned
	assert.InDelta(t, 25.0, ratio, 0.1) // 5/20 = 25%
}

// TestCloseCleanup tests that Close properly cleans up state
func TestCloseCleanup(t *testing.T) {
	cache := New(50)
	cache.SetTotalTemplates(20)

	host := "cleanup-test.example.com:80"

	// Create a honeypot
	for i := 0; i < 15; i++ {
		cache.RecordMatch(host, "template-"+string(rune('a'+i)), "")
	}

	assert.True(t, cache.IsHoneypot(host))

	// Close should clean up
	cache.Close()

	// After close, state should be reset
	assert.False(t, cache.IsHoneypot(host), "honeypot state should be cleared after Close")
	matches, _, _ := cache.GetStats(host)
	assert.Equal(t, 0, matches, "matches should be cleared after Close")
}

// TestVerboseMode tests that verbose mode can be set
func TestVerboseMode(t *testing.T) {
	cache := New(50)
	assert.False(t, cache.verbose)

	cache.SetVerbose(true)
	assert.True(t, cache.verbose)

	cache.SetVerbose(false)
	assert.False(t, cache.verbose)
}
