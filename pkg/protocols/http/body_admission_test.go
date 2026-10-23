package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLargeBodyAdmissionUsesMemoryBudget(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	require.EqualValues(t, 48<<20, admission.limit)

	releases := make([]func(), 0, 2)
	for range 2 {
		release, err := admission.acquire(t.Context(), 20<<20)
		require.NoError(t, err)
		releases = append(releases, release)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := admission.acquire(ctx, 20<<20)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	releases[0]()
	release, err := admission.acquire(t.Context(), 20<<20)
	require.NoError(t, err)
	release()
	releases[1]()
}

func TestSmallBodyBypassesLargeBodyAdmission(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	fullRelease, err := admission.acquire(t.Context(), admission.limit)
	require.NoError(t, err)
	defer fullRelease()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	release, err := admission.acquire(ctx, largeBodyThreshold-1)
	require.NoError(t, err)
	release()
}
