package dsl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGoidParsesStackHeader fails if the runtime.Stack header format changes,
// which would otherwise make file() silently lose its sandbox context.
func TestGoidParsesStackHeader(t *testing.T) {
	id := goid()
	require.NotZero(t, id)
	require.Equal(t, id, goid())

	other := make(chan uint64)
	go func() { other <- goid() }()
	otherID := <-other
	require.NotZero(t, otherID)
	require.NotEqual(t, id, otherID)
}
