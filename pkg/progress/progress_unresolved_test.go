package progress

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkippedUnresolvedCounter(t *testing.T) {
	p, err := NewStatsTicker(-1, false, false, false, 0)
	require.NoError(t, err)
	p.Init(1, 1, 10)
	counter, ok := p.(UnresolvedCounter)
	require.True(t, ok)
	require.Equal(t, uint64(0), counter.SkippedUnresolved())

	counter.IncrementSkippedUnresolved(1)
	counter.IncrementSkippedUnresolved(2)
	require.Equal(t, uint64(3), counter.SkippedUnresolved())
}
