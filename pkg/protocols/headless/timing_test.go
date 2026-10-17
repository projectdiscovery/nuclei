package headless

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/stretchr/testify/require"
)

func TestHeadlessTimingTraceIsTemplateOptIn(t *testing.T) {
	t.Setenv(headlessTimingTemplatesEnv, "")
	require.Nil(t, newHeadlessTimingTrace("headless-open-redirect", "https://example.com"))

	t.Setenv(headlessTimingTemplatesEnv, "CVE-2025-8191, headless-open-redirect")
	require.Nil(t, newHeadlessTimingTrace("other-template", "https://example.com"))

	trace := newHeadlessTimingTrace("headless-open-redirect", "https://example.com")
	require.NotNil(t, trace)
	require.Len(t, trace.targetFingerprint, 16)
	require.NotContains(t, trace.targetFingerprint, "example.com")
}

func TestHeadlessTimingTraceAccountsForActionsAndOverhead(t *testing.T) {
	trace := &headlessTimingTrace{
		templateID:        "headless-open-redirect",
		targetFingerprint: "0123456789abcdef",
		sampled:           true,
		attempts:          2,
		errors:            1,
		rateWait:          time.Second,
		contextCreate:     time.Second,
		cleanup:           250 * time.Millisecond,
	}
	steps := []*engine.Action{
		{ActionType: engine.ActionTypeHolder{ActionType: engine.ActionNavigate}},
		{ActionType: engine.ActionTypeHolder{ActionType: engine.ActionWaitLoad}},
		{ActionType: engine.ActionTypeHolder{ActionType: engine.ActionWaitDialog}},
	}
	trace.recordRun(steps, []time.Duration{2 * time.Second, 500 * time.Millisecond, 3 * time.Second}, 6*time.Second)

	message, ok := trace.summary(30 * time.Second)
	require.True(t, ok)
	for _, field := range []string{
		"attempts=2", "errors=1", "total_ms=30000", "rate_wait_ms=1000",
		"context_create_ms=1000", "navigate_ms=2000", "waitload_ms=500",
		"waitdialog_ms=3000", "run_other_ms=500", "cleanup_ms=250", "unattributed_ms=21750",
	} {
		require.True(t, strings.Contains(message, field), "missing %s in %s", field, message)
	}
	require.NotContains(t, message, "https://")
}

func TestHeadlessTimingTraceBoundsOutput(t *testing.T) {
	trace := &headlessTimingTrace{sampled: false}
	_, ok := trace.summary(4 * time.Minute)
	require.False(t, ok)
	_, ok = trace.summary(5 * time.Minute)
	require.True(t, ok)

	trace.sampled = true
	_, ok = trace.summary(29 * time.Second)
	require.False(t, ok)
	_, ok = trace.summary(30 * time.Second)
	require.True(t, ok)
}

func TestHeadlessTimingTraceDoesNotMisattributePartialActionDurations(t *testing.T) {
	trace := &headlessTimingTrace{sampled: true}
	steps := []*engine.Action{
		{ActionType: engine.ActionTypeHolder{ActionType: engine.ActionNavigate}},
		{ActionType: engine.ActionTypeHolder{ActionType: engine.ActionWaitLoad}},
	}
	trace.recordRun(steps, []time.Duration{2 * time.Second}, 3*time.Second)

	require.Zero(t, trace.navigate)
	require.Zero(t, trace.waitLoad)
	require.Equal(t, 2*time.Second, trace.otherActions)
	require.Equal(t, time.Second, trace.runOther)
}
