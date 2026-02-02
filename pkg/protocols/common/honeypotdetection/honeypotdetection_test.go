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
