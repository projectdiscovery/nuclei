package headless

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/stretchr/testify/require"
)

type timingCaptureWriter struct{ buffer *bytes.Buffer }

func (w timingCaptureWriter) Write(data []byte, _ levels.Level) {
	w.buffer.Write(data)
}

func TestHeadlessTimingTraceUsesExecutionLogger(t *testing.T) {
	previous := gologger.DefaultLogger
	t.Cleanup(func() { gologger.DefaultLogger = previous })
	var output bytes.Buffer
	silentLogger := &gologger.Logger{}
	silentLogger.SetFormatter(formatter.NewCLI(false))
	silentLogger.SetWriter(timingCaptureWriter{buffer: &output})
	silentLogger.SetMaxLevel(levels.LevelSilent)
	gologger.DefaultLogger = silentLogger
	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(timingCaptureWriter{buffer: &output})
	logger.SetMaxLevel(levels.LevelInfo)
	trace := &headlessTimingTrace{templateID: "headless-open-redirect", sampled: true, started: time.Now().Add(-31 * time.Second)}

	trace.emit(silentLogger)
	trace.emit(nil)
	require.Empty(t, output.String())

	trace.emit(logger)
	require.Contains(t, output.String(), "slow headless timing template_id=\"headless-open-redirect\"")
}

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

func TestHeadlessTimingTraceAttributesFailedActions(t *testing.T) {
	trace := &headlessTimingTrace{sampled: true}
	trace.recordFailedRun([]headlessActionTiming{
		{action: engine.ActionNavigate, duration: 2 * time.Second},
		{action: engine.ActionWaitLoad, duration: 500 * time.Millisecond},
	}, 3*time.Second)

	require.Equal(t, 2*time.Second, trace.navigate)
	require.Equal(t, 500*time.Millisecond, trace.waitLoad)
	require.Zero(t, trace.otherActions)
	require.Equal(t, 500*time.Millisecond, trace.runOther)
}
