package httpbody

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// MinBudgetedBody is the smallest body that waits on a Budget, so small
// requests never queue behind a heavy one.
const MinBudgetedBody = 1 << 20

// Budget bounds the request-body bytes held by requests in flight.
type Budget struct {
	size int64
	sem  *semaphore.Weighted
}

// NewBudget returns nil when size <= 0; a nil budget never blocks.
func NewBudget(size int64) *Budget {
	if size <= 0 {
		return nil
	}
	return &Budget{size: size, sem: semaphore.NewWeighted(size)}
}

// Acquire blocks until n bytes fit or ctx is done. n larger than the budget
// is clamped, so that request runs alone.
func (b *Budget) Acquire(ctx context.Context, n int64) (release func(), err error) {
	if b == nil || n < MinBudgetedBody {
		return func() {}, nil
	}
	n = min(n, b.size)
	if err := b.sem.Acquire(ctx, n); err != nil {
		return nil, err
	}
	return func() { b.sem.Release(n) }, nil
}
