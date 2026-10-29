package http

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
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

// makeReserved builds the next request inside a body reservation, waiting
// for budget until waitCtx ends. On success the caller owns the reservation
// and calls done once the send ends.
func (request *Request) makeReserved(waitCtx context.Context, generator *requestGenerator, input *contextargs.Context, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, *bodyReservation, error) {
	reservation, err := request.reserveBody(waitCtx)
	if err != nil {
		return nil, nil, err
	}
	generated, err := generator.Make(input.Context(), input, data, payloads, dynamicValues)
	if err == nil {
		err = reservation.built(waitCtx, request, generated.bodyLen())
	}
	if err != nil {
		reservation.done()
		return nil, nil, err
	}
	generated.bodyReserved = true
	return generated, reservation, nil
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
