package progress

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkippedUnresolvedCounter(t *testing.T) {
	p, err := NewStatsTicker(-1, false, false, false, 0)
	require.NoError(t, err)
	p.Init(1, 1, 10)
	require.Equal(t, uint64(0), p.SkippedUnresolved())

	p.IncrementSkippedUnresolved(1)
	p.IncrementSkippedUnresolved(2)
	require.Equal(t, uint64(3), p.SkippedUnresolved())
}
