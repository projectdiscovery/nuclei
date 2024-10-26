package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseRawRequest(t *testing.T) {
	parsed, err := parseRawRequest(PostReuestsHandlerRequest{
		URL:     "http://example.com/testpath",
		RawHTTP: "GET /testpath HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\n",
	})
	require.NoError(t, err)
	require.Equal(t, "http://example.com/testpath", parsed.URL.String())

	// Example POST request
	parsed, err = parseRawRequest(PostReuestsHandlerRequest{
		URL:     "http://example.com",
		RawHTTP: "POST /testpath HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nContent-Length: 5\n\nhello",
	})
	require.NoError(t, err)
	require.Equal(t, "hello", parsed.Request.Body)
}
