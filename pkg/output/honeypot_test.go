package output

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHoneypotDetector(t *testing.T) {
	options := &types.Options{
		DetectHoneypot:    true,
		HoneypotThreshold: 3,
	}

	detector := NewHoneypotDetector(options)

	// Add 2 matches for same host with different port/scheme to test normalization
	detector.AddMatch("example.com", "template1")
	detector.AddMatch("https://example.com:443", "template2")

	require.Equal(t, 2, len(detector.matches["example.com"]))
	_, warned := detector.warned.Load("example.com")
	require.False(t, warned)

	// Add 3rd match, should trigger warning and CLEANUP the matches map
	detector.AddMatch("example.com:80", "template3")

	require.Equal(t, 0, len(detector.matches["example.com"])) // Memory freed
	_, warned = detector.warned.Load("example.com")
	require.True(t, warned)

	// Add 4th match, should fast-path return
	detector.AddMatch("example.com", "template4")
	require.Equal(t, 0, len(detector.matches["example.com"]))
}

func TestHoneypotDetectorDisabled(t *testing.T) {
	options := &types.Options{
		DetectHoneypot:    false,
		HoneypotThreshold: 3,
	}

	detector := NewHoneypotDetector(options)

	detector.AddMatch("example.com", "template1")
	detector.AddMatch("example.com", "template2")
	detector.AddMatch("example.com", "template3")

	require.Equal(t, 0, len(detector.matches))
}
