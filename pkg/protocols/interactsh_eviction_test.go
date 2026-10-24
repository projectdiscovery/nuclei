package protocols

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInteractshEvictionDuration(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Duration(0), (*ExecutorOptions)(nil).InteractshEvictionDuration())
	require.Equal(t, time.Duration(0), (&ExecutorOptions{}).InteractshEvictionDuration())
	require.Equal(t, 300*time.Second, (&ExecutorOptions{InteractshEviction: 300}).InteractshEvictionDuration())
}
