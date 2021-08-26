package dsl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDSLURLEncodeDecode(t *testing.T) {
	functions := HelperFunctions()

	encoded, err := functions["url_encode"]("&test\"")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := functions["url_decode"]("%26test%22")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "&test\"", decoded, "could not get url decoded data")
}
