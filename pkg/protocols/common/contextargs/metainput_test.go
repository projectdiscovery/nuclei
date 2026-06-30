package contextargs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetaInputMarshalAndUnmarshalString(t *testing.T) {
	input := NewMetaInput()
	input.Input = "https://example.com"
	input.CustomIP = "192.0.2.10"

	encoded, err := input.MarshalString()
	require.NoError(t, err)
	require.Equal(t, "{\"input\":\"https://example.com\",\"customIP\":\"192.0.2.10\"}\n", encoded)

	decoded := NewMetaInput()
	require.NoError(t, decoded.Unmarshal(encoded))
	require.Equal(t, input.Input, decoded.Input)
	require.Equal(t, input.CustomIP, decoded.CustomIP)
}
