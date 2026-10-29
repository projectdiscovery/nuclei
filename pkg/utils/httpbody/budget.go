package httpbody

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// MinBudgetedBody is the smallest body that waits on a Budget. The semaphore
// is FIFO, so a heavy request queued at the front would otherwise stall every
// small request behind it.
const MinBudgetedBody = 1 << 20

// Budget bounds the request-body bytes held by requests in flight, so many
// concurrent heavy requests queue instead of all materialising their bodies
// at once.
type Budget struct {
	size int64
	sem  *semaphore.Weighted
}

// NewBudget returns a budget of size bytes, or nil when size is 0 or less.
// A nil budget never blocks.
func NewBudget(size int64) *Budget {
	if size <= 0 {
		return nil
	}
	return &Budget{size: size, sem: semaphore.NewWeighted(size)}
}

// Acquire blocks until n bytes fit in the budget or ctx is done, and returns
// the function that gives them back. A body larger than the whole budget
// waits for it to empty and then runs alone.
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
