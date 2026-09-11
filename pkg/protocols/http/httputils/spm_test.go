package httputils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireHonoursCancelledContextWhenPoolIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	handler := NewBlockingSPMHandler[error](ctx, 1, 1, false)
	defer handler.Cancel()

	require.NoError(t, handler.Acquire())

	done := make(chan error, 1)
	go func() {
		done <- handler.Acquire()
	}()

	select {
	case <-done:
		t.Fatal("Acquire returned while the pool is full")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire stayed blocked after cancel")
	}
}
