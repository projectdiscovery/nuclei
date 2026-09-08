package stats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrackErrorKind(t *testing.T) {
	tracker := NewTracker()

	// Test single increment
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind timeout count to be 1, got %v", count)
	}

	// Test multiple increments
	tracker.TrackErrorKind("timeout")
	if count, _ := tracker.errorCodes.Get("timeout"); count == nil || count.Load() != 2 {
		t.Errorf("expected error kind timeout count to be 2, got %v", count)
	}

	// Test different error kind
	tracker.TrackErrorKind("connection-refused")
	if count, _ := tracker.errorCodes.Get("connection-refused"); count == nil || count.Load() != 1 {
		t.Errorf("expected error kind connection-refused count to be 1, got %v", count)
	}
}

func TestTrackWaf_Detect(t *testing.T) {
	tracker := NewTracker()

	tracker.TrackWAFDetected("Attention Required! | Cloudflare")
	if count, _ := tracker.wafDetected.Get("cloudflare"); count == nil || count.Load() != 1 {
		t.Errorf("expected waf detected count to be 1, got %v", count)
	}
}

func TestTrackersShareDetectorButNotCounters(t *testing.T) {
	first := NewTracker()
	second := NewTracker()

	require.Same(t, first.wafDetector, second.wafDetector)

	first.TrackStatusCode("200")
	first.TrackErrorKind("timeout")
	first.TrackWAFDetected("Attention Required! | Cloudflare")

	require.Equal(t, 1, first.GetStats().StatusCodeStats["200"])
	require.Equal(t, 1, first.GetStats().ErrorStats["timeout"])
	require.Equal(t, 1, first.GetStats().WAFStats["CloudFlare"])
	require.Empty(t, second.GetStats().StatusCodeStats)
	require.Empty(t, second.GetStats().ErrorStats)
	require.Empty(t, second.GetStats().WAFStats)
}
