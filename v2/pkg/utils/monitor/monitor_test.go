package monitor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMonitorCompareStringSliceEqual(t *testing.T) {
	value := compareStringSliceEqual([]string{"a", "b"}, []string{"b", "a"})
	require.True(t, value, "could not get correct value")

	value = compareStringSliceEqual([]string{"a", "c"}, []string{"b", "a"})
	require.False(t, value, "could get incorrect value")
}
