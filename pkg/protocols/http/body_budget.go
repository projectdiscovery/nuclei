package http

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
)

// bodySizeEstimate is the largest request body a template has built so far.
// The body size is only known once the template's DSL has run, so the first
// build of a template runs alone and records it.
type bodySizeEstimate struct {
	known atomic.Bool
	max   atomic.Int64
	// learning is held by the build that records the first size.
	learning sync.Mutex
}

// bodyReservation is the part of the request body budget a request holds
// from before its body is built until the request is done.
type bodyReservation struct {
	budget  *httpbody.Budget
	size    int64
	release func()
	unlock  func()
}

func noop() {}

// reserveBody takes the template's largest body size seen so far from the
// body budget, so concurrent builds of multi-MB bodies queue instead of all
// allocating at once. Before any size is known the caller builds alone
// instead. Call built once the body exists, and done when the request ends.
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

// built records the size of the body just built and grows the reservation
// to it. Growing releases and acquires again rather than waiting while
// holding part of the budget, which could deadlock two growing requests.
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
