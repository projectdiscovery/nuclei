package dsl

import (
	"testing"

	"github.com/projectdiscovery/nebula"
	"github.com/stretchr/testify/require"
)

func TestDSLURLEncodeDecode(t *testing.T) {
	encoded, err := nebula.EvalExp("url_encode('&test\"')", nil)
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := nebula.EvalExp("url_decode('%26test%22')", nil)
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "&test\"", decoded, "could not get url decoded data")
}
