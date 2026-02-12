package projectfile

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheKeySchemeIsolation(t *testing.T) {
	pf, err := New(&Options{Path: t.TempDir(), Cleanup: true})
	require.NoError(t, err)
	defer pf.Close()

	reqData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Store a response for the HTTPS URL
	httpsResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Test": []string{"https"}},
	}
	err = pf.SetWithURL(reqData, "https://example.com", httpsResp, []byte("https body"))
	require.NoError(t, err)

	// The HTTPS URL should retrieve the cached response
	got, err := pf.GetWithURL(reqData, "https://example.com")
	require.NoError(t, err)
	require.Equal(t, 200, got.StatusCode)

	// The HTTP URL with the same request data must NOT hit the HTTPS cache
	_, err = pf.GetWithURL(reqData, "http://example.com")
	require.ErrorIs(t, err, ErrNotFound, "HTTP request should not match HTTPS cache entry")
}
