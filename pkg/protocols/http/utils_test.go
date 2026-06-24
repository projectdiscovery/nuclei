package http

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHTTPProjectCacheScope_SeparatesSchemeAndPort(t *testing.T) {
	requestDump := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	httpScoped := getHTTPProjectCacheScope(requestDump, "http", "example.com:80")
	httpsScoped := getHTTPProjectCacheScope(requestDump, "https", "example.com:443")

	require.NotEqual(t, httpScoped, httpsScoped)
	require.True(t, bytes.HasSuffix(httpScoped, requestDump))
	require.True(t, bytes.HasSuffix(httpsScoped, requestDump))
}
