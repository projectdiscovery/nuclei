package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMonitorCompareStringSliceEqual(t *testing.T) {
	value := compareStringSliceEqual([]string{"a", "b"}, []string{"b", "a"})
	require.True(t, value, "could not get correct value")

	value = compareStringSliceEqual([]string{"a", "c"}, []string{"b", "a"})
	require.False(t, value, "could get incorrect value")
}

func TestAgentRunExitsWhenCancelled(t *testing.T) {
	// Given
	monitor := NewStackMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(time.Hour)
	t.Cleanup(cancel)
	done := make(chan struct{})

	// When
	go func() {
		monitor.run(ctx, ticker, func() {})
		close(done)
	}()
	cancel()

	// Then
	select {
	case <-done:
	case <-time.After(time.Second):
		require.Fail(t, "monitor goroutine did not exit after cancellation")
	}
}
