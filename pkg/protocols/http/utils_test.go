package http

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/raw"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestGetHTTPProjectCacheScope_SeparatesSchemeAndPort(t *testing.T) {
	dumped := requestDump{data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")}

	httpScoped := getHTTPProjectCacheScope(dumped, nil, "http", "example.com:80")
	httpsScoped := getHTTPProjectCacheScope(dumped, nil, "https", "example.com:443")

	require.NotEqual(t, httpScoped, httpsScoped)
	require.True(t, bytes.HasSuffix(httpScoped, dumped.data))
	require.True(t, bytes.HasSuffix(httpsScoped, dumped.data))
}

func TestDumpRequestMatchesRetryableHTTPDump(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		body    string
		headers map[string]string
		host    string
	}{
		{name: "get", method: http.MethodGet, url: "http://example.com/path?a=1"},
		{name: "head", method: http.MethodHead, url: "http://example.com/"},
		{name: "post body", method: http.MethodPost, url: "http://example.com/submit", body: "a=1&b=2", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
		{name: "https", method: http.MethodPost, url: "https://example.com:8443/x", body: "{}"},
		{name: "custom host", method: http.MethodGet, url: "http://127.0.0.1/", host: "virtual.example"},
		{name: "headers", method: http.MethodPut, url: "http://example.com/", body: "data", headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz", "X-Custom": "1", "User-Agent": "nuclei"}},
		{name: "accept encoding", method: http.MethodGet, url: "http://example.com/", headers: map[string]string{"Accept-Encoding": "br"}},
		{name: "range", method: http.MethodGet, url: "http://example.com/", headers: map[string]string{"Range": "bytes=0-10"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			build := func(withHTTPBody bool) *retryablehttp.Request {
				urlx, err := urlutil.ParseAbsoluteURL(tt.url, true)
				require.NoError(t, err)
				var body interface{}
				if !withHTTPBody && tt.body != "" {
					body = tt.body
				}
				req, err := retryablehttp.NewRequestFromURLWithContext(context.Background(), tt.method, urlx, body)
				require.NoError(t, err)
				if withHTTPBody && tt.body != "" {
					httpbody.SetString(req, tt.body)
				}
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
				if tt.host != "" {
					req.Host = tt.host
				}
				return req
			}

			expected, err := build(false).Dump()
			require.NoError(t, err)
			actual, err := dumpRequest(build(true), 0)
			require.NoError(t, err)
			require.Equal(t, string(expected), string(actual.data))
			require.Zero(t, actual.truncated)
		})
	}
}

func TestDumpRequestTruncatesLargeBody(t *testing.T) {
	body := strings.Repeat("A", 1024*1024)
	req, err := retryablehttp.NewRequest(http.MethodPost, "http://example.com/", nil)
	require.NoError(t, err)
	httpbody.SetString(req, body)

	dumped, err := dumpRequest(req, 100)
	require.NoError(t, err)
	require.Equal(t, len(body)-100, dumped.truncated)

	headers, rest, found := strings.Cut(string(dumped.data), "\r\n\r\n")
	require.True(t, found)
	require.Contains(t, headers, "Content-Length: 1048576", "headers must keep the real length")
	require.Equal(t, strings.Repeat("A", 100)+"\n...[truncated 1048476 bytes]", rest)

	full, err := dumpRequest(req, 0)
	require.NoError(t, err)
	require.Zero(t, full.truncated)
	require.True(t, strings.HasSuffix(string(full.data), body))

	capped := capDumpBody(full.data, 100)
	_, rest, found = strings.Cut(string(capped), "\r\n\r\n")
	require.True(t, found)
	require.Equal(t, strings.Repeat("A", 100)+"\n...[truncated 1048476 bytes]", rest)
	require.Equal(t, full.data, capDumpBody(full.data, 0))
	require.Equal(t, full.data, capDumpBody(full.data, len(body)))
}

func TestDumpRawRequestTruncatesLargeBody(t *testing.T) {
	generated := &generatedRequest{rawRequest: &raw.Request{
		Method:  http.MethodPost,
		Path:    "/",
		Headers: map[string]string{"Host": "example.com", "Content-Length": "5000"},
		Data:    strings.Repeat("B", 5000),
	}}

	dumped, err := dump(generated, "http://example.com/", 1000)
	require.NoError(t, err)
	require.Equal(t, 4000, dumped.truncated)
	require.Contains(t, string(dumped.data), "Content-Length: 5000")
	require.True(t, strings.HasSuffix(string(dumped.data), strings.Repeat("B", 1000)+"\n...[truncated 4000 bytes]"))
}

func TestGetHTTPProjectCacheScope_HashesTruncatedBody(t *testing.T) {
	dumped := requestDump{data: []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\nAAAA\n...[truncated 4 bytes]"), truncated: 4}

	first := getHTTPProjectCacheScope(dumped, []byte("AAAABBBB"), "http", "example.com")
	second := getHTTPProjectCacheScope(dumped, []byte("AAAACCCC"), "http", "example.com")
	require.NotEqual(t, first, second, "bodies differing after the cap must get different keys")
}
