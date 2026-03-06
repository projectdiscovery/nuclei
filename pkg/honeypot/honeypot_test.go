package honeypot

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		{"http://example.com:8080/path?q=1", "example.com:8080"},
		{"example.com", "example.com"},
		{"example.com:8080", "example.com:8080"},
		{"example.com:80", "example.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:9090", "192.168.1.1:9090"},
		{"[::1]", "::1"},
		{"[::1]:8080", "::1:8080"},
		{"[::1]:80", "::1"},
		{"", ""},
		{"  http://example.com  ", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeHost(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectorDisabled(t *testing.T) {
	d := New(Options{Threshold: 0})
	require.False(t, d.Enabled())
	require.False(t, d.RecordMatch("host", "template"))
	require.False(t, d.IsFlagged("host"))
	require.False(t, d.ShouldSuppress("host"))
	require.Equal(t, 0, d.MatchCount("host"))
	require.Empty(t, d.FlaggedHosts())
}

func TestDetectorNil(t *testing.T) {
	var d *Detector
	require.False(t, d.Enabled())
	require.Equal(t, 0, d.FlaggedCount())
}

func TestDetectorThreshold(t *testing.T) {
	var warned sync.Map
	d := New(Options{Threshold: 3})
	d.SetWarnFunc(func(host string, count int) {
		warned.Store(host, count)
	})

	host := "http://example.com/path"

	// First two matches - not flagged
	require.False(t, d.RecordMatch(host, "template-1"))
	require.False(t, d.RecordMatch(host, "template-2"))
	require.False(t, d.IsFlagged(host))
	require.Equal(t, 2, d.MatchCount(host))

	// Third match - crosses threshold
	require.True(t, d.RecordMatch(host, "template-3"))
	require.True(t, d.IsFlagged(host))
	require.Equal(t, 3, d.MatchCount(host))

	// Verify warning was emitted
	val, ok := warned.Load("example.com")
	require.True(t, ok)
	require.Equal(t, 3, val)

	// Subsequent matches still flagged
	require.True(t, d.RecordMatch(host, "template-4"))
}

func TestDetectorDuplicateTemplates(t *testing.T) {
	d := New(Options{Threshold: 3})
	d.SetWarnFunc(func(string, int) {})

	host := "http://example.com"

	// Same template twice should count as 1
	require.False(t, d.RecordMatch(host, "template-1"))
	require.False(t, d.RecordMatch(host, "template-1"))
	require.Equal(t, 1, d.MatchCount(host))
}

func TestDetectorMultipleHosts(t *testing.T) {
	d := New(Options{Threshold: 2})
	d.SetWarnFunc(func(string, int) {})

	d.RecordMatch("http://host-a.com", "t1")
	d.RecordMatch("http://host-a.com", "t2")
	d.RecordMatch("http://host-b.com", "t1")

	require.True(t, d.IsFlagged("http://host-a.com"))
	require.False(t, d.IsFlagged("http://host-b.com"))
	require.Equal(t, 1, d.FlaggedCount())

	flagged := d.FlaggedHosts()
	require.Len(t, flagged, 1)
	require.Equal(t, "host-a.com", flagged[0].Host)
	require.Equal(t, 2, flagged[0].MatchCount)
}

func TestDetectorSuppression(t *testing.T) {
	// With suppress disabled
	d := New(Options{Threshold: 2, Suppress: false})
	d.SetWarnFunc(func(string, int) {})

	d.RecordMatch("http://example.com", "t1")
	d.RecordMatch("http://example.com", "t2")

	require.True(t, d.IsFlagged("http://example.com"))
	require.False(t, d.ShouldSuppress("http://example.com"))

	// With suppress enabled
	d2 := New(Options{Threshold: 2, Suppress: true})
	d2.SetWarnFunc(func(string, int) {})

	d2.RecordMatch("http://example.com", "t1")
	d2.RecordMatch("http://example.com", "t2")

	require.True(t, d2.IsFlagged("http://example.com"))
	require.True(t, d2.ShouldSuppress("http://example.com"))
}

func TestDetectorConcurrency(t *testing.T) {
	d := New(Options{Threshold: 50})
	d.SetWarnFunc(func(string, int) {})

	var wg sync.WaitGroup
	var flaggedCount atomic.Int32

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			templateID := fmt.Sprintf("template-%d", idx)
			if d.RecordMatch("http://target.com", templateID) {
				flaggedCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	require.True(t, d.IsFlagged("http://target.com"))
	// Once flagged, concurrent goroutines may skip adding to the tracker
	// (fast path returns early). So match count is at least the threshold.
	require.GreaterOrEqual(t, d.MatchCount("http://target.com"), 50)
	require.Greater(t, int(flaggedCount.Load()), 0)
}

func TestDetectorEmptyHost(t *testing.T) {
	d := New(Options{Threshold: 3})
	require.False(t, d.RecordMatch("", "template-1"))
	require.False(t, d.IsFlagged(""))
	require.Equal(t, 0, d.MatchCount(""))
}

func TestContainsKnownSignature(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		found    bool
		expected string
	}{
		{"cowrie ssh", "SSH-2.0-OpenSSH_6.0p1 Cowrie", true, "cowrie"},
		{"dionaea", "Server: dionaea/0.1", true, "dionaea"},
		{"conpot header", "Conpot SCADA Honeypot", true, "conpot"},
		{"glastopf", "Powered by Glastopf", true, "glastopf"},
		{"case insensitive", "ELASTICHONEY trap", true, "elastichoney"},
		{"no match", "Apache/2.4.52 (Ubuntu)", false, ""},
		{"empty", "", false, ""},
		{"kippo", "Using default handler: kippo", true, "kippo"},
		{"opencanary", "opencanary service running", true, "opencanary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, sig := ContainsKnownSignature(tt.data)
			require.Equal(t, tt.found, found)
			require.Equal(t, tt.expected, sig)
		})
	}
}

func TestDetectorWarningOnlyOnce(t *testing.T) {
	var warnCount atomic.Int32
	d := New(Options{Threshold: 2})
	d.SetWarnFunc(func(string, int) {
		warnCount.Add(1)
	})

	// Cross threshold
	d.RecordMatch("http://example.com", "t1")
	d.RecordMatch("http://example.com", "t2")

	// Additional matches after flagging should not warn again
	d.RecordMatch("http://example.com", "t3")
	d.RecordMatch("http://example.com", "t4")

	require.Equal(t, int32(1), warnCount.Load())
}

func TestDetectorURLVariationsNormalize(t *testing.T) {
	d := New(Options{Threshold: 3})
	d.SetWarnFunc(func(string, int) {})

	// Same host via different URL forms should be tracked together
	d.RecordMatch("http://example.com/path1", "t1")
	d.RecordMatch("https://example.com/path2", "t2")
	d.RecordMatch("example.com", "t3")

	require.True(t, d.IsFlagged("example.com"))
	require.Equal(t, 3, d.MatchCount("example.com"))
}
