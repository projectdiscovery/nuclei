package stringslice

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawStringSliceStringNilSafe(t *testing.T) {
	var nilSlice *RawStringSlice
	require.Equal(t, "", nilSlice.String())
	require.Equal(t, "", fmt.Sprint(nilSlice))
	require.Equal(t, "a, b", NewRawStringSlice([]string{"a", "b"}).String())
}
