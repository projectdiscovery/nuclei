package compiler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	syncutil "github.com/projectdiscovery/utils/sync"
)

// TestAddWithContextRespectsDeadline verifies that AddWithContext returns an
// error when the context deadline expires while waiting for a pool slot.
// Before the fix, Add() used t.Context() and would block indefinitely.
func TestAddWithContextRespectsDeadline(t *testing.T) {
	pool, err := syncutil.New(syncutil.WithSize(1))
	require.NoError(t, err)

	// Fill the only slot.
	pool.Add()
	defer pool.Done()

	// Try to acquire with a short deadline, should fail fast and not hang.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = pool.AddWithContext(ctx)
	elapsed := time.Since(start)

	require.Error(t, err, "AddWithContext should fail when pool is full and deadline expires")
	require.Less(t, elapsed, 200*time.Millisecond, "AddWithContext should fail fast after deadline")
}