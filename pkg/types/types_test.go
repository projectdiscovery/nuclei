package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionsCopyIncludesHoneypotFields(t *testing.T) {
	original := &Options{
		HoneypotThreshold:       7,
		HoneypotSuppressResults: true,
	}

	copied := original.Copy()
	require.NotNil(t, copied)
	require.Equal(t, 7, copied.HoneypotThreshold)
	require.True(t, copied.HoneypotSuppressResults)
}
