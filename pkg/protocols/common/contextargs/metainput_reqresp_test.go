package contextargs

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

// TestMetaInputMarshalStringWithReqRespRoundTrip covers the exact producer /
// consumer pair used by the input list (hmap.go): a MetaInput carrying a
// captured request must survive MarshalString -> Unmarshal.
func TestMetaInputMarshalStringWithReqRespRoundTrip(t *testing.T) {
	rr, err := types.ParseRawRequest("GET /admin?token=abc HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	in := NewMetaInput()
	in.ReqResp = rr
	in.Input = rr.URL.String()

	key, err := in.MarshalString()
	require.NoError(t, err)
	require.False(t, strings.Contains(key, "eyJ"), "request must not be base64-wrapped: %s", key)

	out := NewMetaInput()
	require.NoError(t, out.Unmarshal(key), "round-trip failed for key: %s", key)
	require.NotNil(t, out.ReqResp)
	require.NotNil(t, out.ReqResp.Request)
	require.Equal(t, "GET", out.ReqResp.Request.Method)
	require.Equal(t, in.Input, out.Input)
}
