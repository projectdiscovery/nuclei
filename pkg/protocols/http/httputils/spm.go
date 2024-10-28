package httputils

import (
	"context"
	"sync"

	syncutil "github.com/projectdiscovery/utils/sync"
	"golang.org/x/exp/maps"
)

// WorkPoolType is the type of work pool to use
type WorkPoolType uint

const (
	// Blocking blocks addition of new work when the pool is full
	Blocking WorkPoolType = iota
	// NonBlocking does not block addition of new work when the pool is full
	NonBlocking
)

// StopAtFirstMatchHandler is a handler that executes
// request and stops on first match
type StopAtFirstMatchHandler[T comparable] struct {
	once sync.Once
	// Result Channel
	ResultChan chan T

	// work pool and its type
	poolType WorkPoolType
	sgPool   *syncutil.AdaptiveWaitGroup
	wgPool   *sync.WaitGroup

	// internal / unexported
	ctx         context.Context
	cancel      context.CancelFunc
	internalWg  *sync.WaitGroup
	results     map[T]struct{}
	onResult    func(T)
	stopEnabled bool
	maxResults  int
}

// NewBlockingSPMHandler creates a new stop at first match handler
func NewBlockingSPMHandler[T comparable](ctx context.Context, size int, maxResults int, spm bool) *StopAtFirstMatchHandler[T] {
	ctx1, cancel := context.WithCancel(ctx)

	awg, _ := syncutil.New(syncutil.WithSize(size))

	s := &StopAtFirstMatchHandler[T]{
		ResultChan:  make(chan T, 1),
		poolType:    Blocking,
		sgPool:      awg,
		internalWg:  &sync.WaitGroup{},
		ctx:         ctx1,
		cancel:      cancel,
		stopEnabled: spm,
		results:     make(map[T]struct{}),
		maxResults:  maxResults,
	}
	s.internalWg.Add(1)
	go s.run(ctx)
	return s
}

// NewNonBlockingSPMHandler creates a new stop at first match handler
func NewNonBlockingSPMHandler[T comparable](ctx context.Context, maxResults int, spm bool) *StopAtFirstMatchHandler[T] {
	ctx1, cancel := context.WithCancel(ctx)
	s := &StopAtFirstMatchHandler[T]{
		ResultChan:  make(chan T, 1),
		poolType:    NonBlocking,
		wgPool:      &sync.WaitGroup{},
		internalWg:  &sync.WaitGroup{},
		ctx:         ctx1,
		cancel:      cancel,
		stopEnabled: spm,
		results:     make(map[T]struct{}),
		maxResults:  maxResults,
	}
	s.internalWg.Add(1)
	go s.run(ctx)
	return s
}

// Trigger triggers the stop at first match handler and stops the execution of
// existing requests
func (h *StopAtFirstMatchHandler[T]) Trigger() {
	if h.stopEnabled {
		h.cancel()
	}
}

// Cancel cancels spm context
func (h *StopAtFirstMatchHandler[T]) Cancel() {
	h.cancel()
}

// SetOnResult callback
// this is not thread safe
func (h *StopAtFirstMatchHandler[T]) SetOnResultCallback(fn func(T)) {
	if h.onResult != nil {
		tmp := h.onResult
		h.onResult = func(t T) {
			tmp(t)
			fn(t)
		}
	} else {
		h.onResult = fn
	}
}

// MatchCallback is called when a match is found
// input fn should be the callback that is intended to be called
// if stop at first is enabled and other conditions are met
// if it does not meet above conditions, use of this function is discouraged
func (h *StopAtFirstMatchHandler[T]) MatchCallback(fn func()) {
	if !h.stopEnabled {
		fn()
		return
	}
	h.once.Do(fn)
}

// run runs the internal handler
func (h *StopAtFirstMatchHandler[T]) run(ctx context.Context) {
	defer h.internalWg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case val, ok := <-h.ResultChan:
			if !ok {
				return
			}
			if h.onResult != nil {
				h.onResult(val)
			}
			if len(h.results) >= h.maxResults {
				// skip or do not store the result
				continue
			}
			h.results[val] = struct{}{}
		}
	}
}

// Done returns a channel with the context done signal when stop at first match is detected
func (h *StopAtFirstMatchHandler[T]) Done() <-chan struct{} {
	return h.ctx.Done()
}

// Cancelled returns true if the context is cancelled
func (h *StopAtFirstMatchHandler[T]) Cancelled() bool {
	return h.ctx.Err() != nil
}

// FoundFirstMatch returns true if first match was found
// in stop at first match mode
func (h *StopAtFirstMatchHandler[T]) FoundFirstMatch() bool {
	if h.ctx.Err() != nil && h.stopEnabled {
		return true
	}
	return false
}

// Acquire acquires a new work
func (h *StopAtFirstMatchHandler[T]) Acquire() {
	switch h.poolType {
	case Blocking:
		h.sgPool.Add()
	case NonBlocking:
		h.wgPool.Add(1)
	}
}

// Release releases a work
func (h *StopAtFirstMatchHandler[T]) Release() {
	switch h.poolType {
	case Blocking:
		h.sgPool.Done()
	case NonBlocking:
		h.wgPool.Done()
	}
}

func (h *StopAtFirstMatchHandler[T]) Resize(ctx context.Context, size int) error {
	if h.sgPool.Size != size {
		return h.sgPool.Resize(ctx, size)
	}
	return nil
}

func (h *StopAtFirstMatchHandler[T]) Size() int {
	return h.sgPool.Size
}

// Wait waits for all work to be done
func (h *StopAtFirstMatchHandler[T]) Wait() {
	switch h.poolType {
	case Blocking:
		h.sgPool.Wait()
	case NonBlocking:
		h.wgPool.Wait()
	}
	// after waiting it closes the error channel
	close(h.ResultChan)
	h.internalWg.Wait()
}

// CombinedResults returns the combined results
func (h *StopAtFirstMatchHandler[T]) CombinedResults() []T {
	return maps.Keys(h.results)
}
