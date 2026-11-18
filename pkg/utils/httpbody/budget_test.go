package httpbody

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBudgetQueuesBodiesOverSize(t *testing.T) {
	budget := NewBudget(48 << 20)

	first, err := budget.Acquire(t.Context(), 20<<20)
	require.NoError(t, err)
	second, err := budget.Acquire(t.Context(), 20<<20)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = budget.Acquire(ctx, 20<<20)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	first()
	third, err := budget.Acquire(t.Context(), 20<<20)
	require.NoError(t, err)
	third()
	second()
}

func TestBudgetRunsBodyLargerThanBudgetAlone(t *testing.T) {
	budget := NewBudget(8 << 20)

	huge, err := budget.Acquire(t.Context(), 64<<20)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = budget.Acquire(ctx, 2<<20)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	huge()
	next, err := budget.Acquire(t.Context(), 2<<20)
	require.NoError(t, err)
	next()
}

func TestBudgetSkipsSmallBodies(t *testing.T) {
	budget := NewBudget(MinBudgetedBody)
	full, err := budget.Acquire(t.Context(), MinBudgetedBody)
	require.NoError(t, err)
	defer full()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	release, err := budget.Acquire(ctx, MinBudgetedBody-1)
	require.NoError(t, err)
	release()
}

func TestNilBudgetNeverBlocks(t *testing.T) {
	require.Nil(t, NewBudget(0))

	var budget *Budget
	release, err := budget.Acquire(t.Context(), 1<<30)
	require.NoError(t, err)
	release()
}
