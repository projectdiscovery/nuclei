package httputils

import (
	"context"
	"testing"
	"time"
)

func TestCancelStopsResultReceiver(t *testing.T) {
	constructors := map[string]func(context.Context) *StopAtFirstMatchHandler[int]{
		"blocking": func(ctx context.Context) *StopAtFirstMatchHandler[int] {
			return NewBlockingSPMHandler[int](ctx, 1, 1, true)
		},
		"nonblocking": func(ctx context.Context) *StopAtFirstMatchHandler[int] {
			return NewNonBlockingSPMHandler[int](ctx, 1, true)
		},
	}

	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			handler := construct(parent)
			done := make(chan struct{})
			go func() {
				handler.internalWg.Wait()
				close(done)
			}()

			handler.Cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("result receiver remained alive after cancellation")
			}
		})
	}
}
