// AuthenticatedScanWait ensures templates wait for secret file authentication
// before executing requests. This fixes the race condition where templates
// start executing before authentication is complete.

package runner

import (
	"context"
	"sync"
	"time"
)

// AuthWaiter manages waiting for authentication to complete
type AuthWaiter struct {
	mu          sync.Mutex
	authed      bool
	waiters     []chan struct{}
	timeout     time.Duration
}

// NewAuthWaiter creates a new AuthWaiter with specified timeout
func NewAuthWaiter(timeout time.Duration) *AuthWaiter {
	return &AuthWaiter{
		waiters: make([]chan struct{}, 0),
		timeout: timeout,
	}
}

// WaitForAuth blocks until authentication is complete or timeout
func (a *AuthWaiter) WaitForAuth(ctx context.Context) error {
	a.mu.Lock()
	if a.authed {
		a.mu.Unlock()
		return nil
	}
	
	ch := make(chan struct{})
	a.waiters = append(a.waiters, ch)
	a.mu.Unlock()
	
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(a.timeout):
		return nil // Don't block indefinitely
	}
}

// MarkAuthed marks authentication as complete and notifies all waiters
func (a *AuthWaiter) MarkAuthed() {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	a.authed = true
	for _, ch := range a.waiters {
		close(ch)
	}
	a.waiters = nil
}
