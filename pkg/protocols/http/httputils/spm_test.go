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

func TestCancelPreservesQueuedResults(t *testing.T) {
	constructors := map[string]func() *StopAtFirstMatchHandler[int]{
		"blocking": func() *StopAtFirstMatchHandler[int] {
			return NewBlockingSPMHandler[int](context.Background(), 1, 2, false)
		},
		"nonblocking": func() *StopAtFirstMatchHandler[int] {
			return NewNonBlockingSPMHandler[int](context.Background(), 2, false)
		},
	}

	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			for range 25 {
				handler := construct()
				entered := make(chan struct{})
				release := make(chan struct{})
				handler.SetOnResultCallback(func(value int) {
					if value == 1 {
						close(entered)
						<-release
					}
				})
				handler.ResultChan <- 1
				<-entered
				handler.ResultChan <- 2
				handler.Cancel()
				close(release)
				handler.Wait()

				found := make(map[int]bool)
				for _, result := range handler.CombinedResults() {
					found[result] = true
				}
				if !found[1] || !found[2] {
					t.Fatalf("queued results lost after cancellation: %v", found)
				}
			}
		})
	}
}
