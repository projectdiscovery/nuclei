package flow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeclaredRequestBodySize(t *testing.T) {
	size, exists, err := declaredRequestBodySize(nil)
	require.NoError(t, err)
	require.False(t, exists)
	require.Zero(t, size)

	size, exists, err = declaredRequestBodySize(map[string]interface{}{"max-request-body-bytes": 20 << 20})
	require.NoError(t, err)
	require.True(t, exists)
	require.EqualValues(t, 20<<20, size)

	_, exists, err = declaredRequestBodySize(map[string]interface{}{"max-request-body-bytes": -1})
	require.True(t, exists)
	require.Error(t, err)
}
