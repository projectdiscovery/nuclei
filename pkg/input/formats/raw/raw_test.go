package raw

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func parseAll(t *testing.T, data string) []*types.RequestResponse {
	t.Helper()
	var got []*types.RequestResponse
	err := New().Parse(strings.NewReader(data), func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test.http")
	require.NoError(t, err)
	return got
}

func TestParseSingleRequest(t *testing.T) {
	got := parseAll(t, "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}")

	require.Len(t, got, 1)
	require.Equal(t, "POST", got[0].Request.Method)
	require.Equal(t, "https://example.com/api/login", got[0].URL.String())
	require.Equal(t, `{"user":"admin"}`, got[0].Request.Body)
	contentType, _ := got[0].Request.Headers.Get("Content-Type")
	require.Equal(t, "application/json", contentType)
}

func TestParseMultipleRequests(t *testing.T) {
	got := parseAll(t, strings.Join([]string{
		"GET /one HTTP/1.1",
		"Host: example.com",
		"",
		"### second request",
		"POST /two HTTP/1.1",
		"Host: example.com",
		"",
		"body=1",
	}, "\n"))

	require.Len(t, got, 2)
	require.Equal(t, "https://example.com/one", got[0].URL.String())
	require.Equal(t, "https://example.com/two", got[1].URL.String())
	require.Equal(t, "body=1", got[1].Request.Body)
}

// A request pasted out of a browser or Burp commonly ends at the last header.
func TestParseWithoutTrailingBlankLine(t *testing.T) {
	got := parseAll(t, "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com")

	require.Len(t, got, 1)
	require.Equal(t, "https://example.com/api/users?id=1", got[0].URL.String())
	require.Empty(t, got[0].Request.Body)
}

// The scheme is not part of an origin-form request, so it is inferred from the
// authority unless the request target states it.
func TestParseResolvesScheme(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		url  string
	}{
		{"no port", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "https://example.com/"},
		{"port 80", "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n", "http://example.com:80/"},
		{"high port", "GET / HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n\r\n", "http://127.0.0.1:18080/"},
		{"absolute target", "GET https://example.com/p HTTP/1.1\r\nHost: example.com\r\n\r\n", "https://example.com/p"},
		{"absolute plain target", "GET http://example.com/p HTTP/1.1\r\nHost: example.com\r\n\r\n", "http://example.com/p"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAll(t, tt.raw)
			require.Len(t, got, 1)
			require.Equal(t, tt.url, got[0].URL.String())
		})
	}
}

// A request with no way to resolve a target is dropped rather than scanned
// against nothing, and it must not take the rest of the file down with it.
func TestParseSkipsRequestsWithoutTarget(t *testing.T) {
	got := parseAll(t, strings.Join([]string{
		"GET /no-host HTTP/1.1",
		"X-Test: 1",
		"",
		"###",
		"GET /valid HTTP/1.1",
		"Host: example.com",
		"",
	}, "\n"))

	require.Len(t, got, 1)
	require.Equal(t, "https://example.com/valid", got[0].URL.String())
}

// The callback's return value is unused across every input format, and its two
// call sites in the provider give it opposite meanings, so a request must be
// reported regardless of what the previous one returned.
func TestParseIgnoresCallbackReturn(t *testing.T) {
	var count int
	err := New().Parse(strings.NewReader("GET /one HTTP/1.1\nHost: example.com\n\n###\nGET /two HTTP/1.1\nHost: example.com\n\n"), func(rr *types.RequestResponse) bool {
		count++
		return true
	}, "test.http")

	require.NoError(t, err)
	require.Equal(t, 2, count)
}

func TestFormatInterface(t *testing.T) {
	var format formats.Format = New()
	require.Equal(t, "http", format.Name())
}
