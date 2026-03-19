package honeypot

import (
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestHoneypotDetector(t *testing.T) {
	opts := &types.Options{
		HoneypotDetectionEnabled: true,
		HoneypotMatchThreshold:   3,
	}
	det := New(opts)

	assert.False(t, det.RecordMatch("host1", "t1"))
	assert.False(t, det.RecordMatch("host1", "t2"))
	assert.True(t, det.RecordMatch("host1", "t3")) // equals threshold

	assert.True(t, det.IsHoneypot("host1"))
	assert.Equal(t, 3, det.GetMatchCount("host1"))

	det.ResetForHost("host1")
	assert.False(t, det.IsHoneypot("host1"))
	assert.Equal(t, 0, det.GetMatchCount("host1"))
}

func TestHoneypotDisabled(t *testing.T) {
	opts := &types.Options{
		HoneypotDetectionEnabled: false,
		HoneypotMatchThreshold:   10,
	}
	det := New(opts)
	assert.False(t, det.RecordMatch("host1", "t1"))
	assert.False(t, det.IsHoneypot("host1"))
}

func TestHoneypotResetInterval(t *testing.T) {
	opts := &types.Options{
		HoneypotDetectionEnabled:    true,
		HoneypotMatchThreshold:      2,
		HoneypotResetIntervalSeconds: 0, // 0 = no reset by default
	}
	det := New(opts)

	det.RecordMatch("host1", "t1")
	det.RecordMatch("host1", "t2")
	assert.True(t, det.IsHoneypot("host1"))
	assert.Equal(t, 2, det.GetMatchCount("host1"))

	// Create new detector with reset interval
	opts2 := &types.Options{
		HoneypotDetectionEnabled:    true,
		HoneypotMatchThreshold:      2,
		HoneypotResetIntervalSeconds: 1, // 1 second
	}
	det2 := New(opts2)

	det2.RecordMatch("host1", "t1")
	det2.RecordMatch("host1", "t2")
	assert.True(t, det2.IsHoneypot("host1"))

	// Wait for reset interval (1.2s)
	time.Sleep(1200 * time.Millisecond)

	// After reset, first record should start fresh
	det2.RecordMatch("host1", "t3")
	assert.Equal(t, 1, det2.GetMatchCount("host1")) // reset to 1, not 3
}
