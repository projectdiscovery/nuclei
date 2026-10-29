package http

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
)

// bodySizeEstimate is the largest request body a template has built so far.
type bodySizeEstimate struct {
	known    atomic.Bool
	max      atomic.Int64
	learning sync.Mutex
}

type bodyReservation struct {
	budget  *httpbody.Budget
	size    int64
	release func()
	unlock  func()
}

func noop() {}

// reserveBody reserves the template's largest body size before the body is
// built. Until a size is known, builds run one at a time.
func (request *Request) reserveBody(ctx context.Context) (*bodyReservation, error) {
	r := &bodyReservation{budget: request.options.RequestBodyBudget, release: noop, unlock: noop}
	estimate := request.bodySize
	if r.budget == nil || estimate == nil {
		return r, nil
	}
	if !estimate.known.Load() {
		estimate.learning.Lock()
		if !estimate.known.Load() {
			r.unlock = estimate.learning.Unlock
			return r, nil
		}
		estimate.learning.Unlock()
	}
	r.size = estimate.max.Load()
	release, err := r.budget.Acquire(ctx, r.size)
	if err != nil {
		return nil, err
	}
	r.release = release
	return r, nil
}

// built grows the reservation to the body's real size. It releases before
// acquiring again: waiting while holding part of the budget can deadlock.
func (r *bodyReservation) built(ctx context.Context, request *Request, size int64) error {
	if estimate := request.bodySize; estimate != nil {
		for {
			seen := estimate.max.Load()
			if size <= seen || estimate.max.CompareAndSwap(seen, size) {
				break
			}
		}
		estimate.known.Store(true)
	}
	r.unlock()
	r.unlock = noop
	if size <= r.size {
		return nil
	}
	r.release()
	r.release = noop
	release, err := r.budget.Acquire(ctx, size)
	if err != nil {
		return err
	}
	r.release, r.size = release, size
	return nil
}

func (r *bodyReservation) done() {
	r.unlock()
	r.release()
}
