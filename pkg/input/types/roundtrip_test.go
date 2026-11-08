package types

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

// TestRequestResponseJSONRoundTrip pins the json.JSONCodec contract asserted
// on RequestResponse: MarshalJSON output must be decodable by the type's own
// UnmarshalJSON.
//
// It previously failed because MarshalJSON put the pre-marshaled request and
// response into a map[string]interface{} as []byte, which encoding/json (and
// sonic) encode as base64 *strings* - while UnmarshalJSON expects JSON
// objects:
//
//	{"request":"eyJtZXRob2QiOiJHRVQifQ==", ...}  -> mismatched type string
//
// MetaInput serializes a captured request as the "raw-request" key with this
// codec, so the broken round-trip surfaced through MetaInput.MarshalString ->
// MetaInput.Unmarshal (pkg/input/provider/list/hmap.go) as a decode error.
func TestRequestResponseJSONRoundTrip(t *testing.T) {
	rr, err := ParseRawRequest("GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nX-Test: hello\r\n\r\nbody")
	require.NoError(t, err)
	rr.Response = &HttpResponse{
		StatusCode: 200,
		Body:       "ok",
		Raw:        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	}

	encoded, err := json.Marshal(rr)
	require.NoError(t, err)

	var decoded RequestResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded), "marshal/unmarshal round-trip must succeed, got %s", encoded)

	require.Equal(t, rr.URL.String(), decoded.URL.String())
	require.NotNil(t, decoded.Request)
	require.Equal(t, rr.Request.Method, decoded.Request.Method)
	require.Equal(t, rr.Request.Raw, decoded.Request.Raw)
	require.Equal(t, rr.Request.Body, decoded.Request.Body)
	require.NotNil(t, decoded.Response)
	require.Equal(t, rr.Response.StatusCode, decoded.Response.StatusCode)
	require.Equal(t, rr.Response.Raw, decoded.Response.Raw)
}

// TestRequestResponseMarshalOmitsNilParts pins that nil Request/Response stay
// nil across the round-trip instead of turning into zero-valued structs (or a
// decode error, which is what the previous base64 "null" encoding produced).
func TestRequestResponseMarshalOmitsNilParts(t *testing.T) {
	rr, err := ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	require.Nil(t, rr.Response)

	encoded, err := json.Marshal(rr)
	require.NoError(t, err)

	var decoded RequestResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded), "got %s", encoded)
	require.NotNil(t, decoded.Request)
	require.Nil(t, decoded.Response)
}
