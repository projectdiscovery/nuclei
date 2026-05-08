package raw

import (
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestTryFillCustomHeaders_BufferDetached(t *testing.T) {
	r := &Request{
		UnsafeRawBytes: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBody"),
	}
	// first fill
	err := r.TryFillCustomHeaders([]string{"X-Test: 1"})
	require.NoError(t, err, "unexpected error on first call")
	prev := r.UnsafeRawBytes
	prevStr := string(prev) // content snapshot
	err = r.TryFillCustomHeaders([]string{"X-Another: 2"})
	require.NoError(t, err, "unexpected error on second call")
	require.Equal(t, prevStr, string(prev), "first slice mutated after second call; buffer not detached")
	require.NotEqual(t, prevStr, string(r.UnsafeRawBytes), "request bytes did not change after second call")
}

func TestParseRawRequestWithPort(t *testing.T) {
	request, err := Parse(`GET /gg/phpinfo.php HTTP/1.1
Host: {{Hostname}}:123
Origin: {{BaseURL}}
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.9`, parseURL(t, "https://example.com:8080"), false, false)
	require.Nil(t, err, "could not parse GET request")
	require.Equal(t, "https://example.com:8080/gg/phpinfo.php", request.FullURL, "Could not parse request url correctly")
	require.Equal(t, "/gg/phpinfo.php", request.Path, "Could not parse request path correctly")

	t.Run("path-suffix", func(t *testing.T) {
		request, err := Parse(`GET /hello HTTP/1.1
Host: {{Hostname}}`, parseURL(t, "https://example.com:8080/test"), false, false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test/hello", request.FullURL, "Could not parse request url correctly")
	})

	t.Run("query-values", func(t *testing.T) {
		request, err := Parse(`GET ?username=test&password=test HTTP/1.1
Host: {{Hostname}}:123`, parseURL(t, "https://example.com:8080/test"), false, false)
		require.Nil(t, err, "could not parse GET request")
		// url.values are sorted to avoid randomness of using maps
		require.Equal(t, "https://example.com:8080/test?username=test&password=test", request.FullURL, "Could not parse request url correctly")

		request, err = Parse(`GET ?username=test&password=test HTTP/1.1
Host: {{Hostname}}:123`, parseURL(t, "https://example.com:8080/test/"), false, false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test/?username=test&password=test", request.FullURL, "Could not parse request url correctly")

		request, err = Parse(`GET /?username=test&password=test HTTP/1.1
		Host: {{Hostname}}:123`, parseURL(t, "https://example.com:8080/test/"), false, false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test/?username=test&password=test", request.FullURL, "Could not parse request url correctly")
	})
}

func TestParseRawRequest(t *testing.T) {
	request, err := Parse(`GET /manager/html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('username:password')}}
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0
Accept-Language: en-US,en;q=0.9
Connection: close`, parseURL(t, "https://test.com"), false, false)
	require.Nil(t, err, "could not parse GET request")
	require.Equal(t, "GET", request.Method, "Could not parse GET method request correctly")
	require.Equal(t, "/manager/html", request.Path, "Could not parse request path correctly")

	request, err = Parse(`POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Connection: close

username=admin&password=login`, parseURL(t, "https://test.com"), false, false)
	require.Nil(t, err, "could not parse POST request")
	require.Equal(t, "POST", request.Method, "Could not parse POST method request correctly")
	require.Equal(t, "username=admin&password=login", request.Data, "Could not parse request data correctly")
}

func TestParseUnsafeRequestWithPath(t *testing.T) {
	request, err := Parse(`GET /manager/html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('username:password')}}
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0
Accept-Language: en-US,en;q=0.9
Connection: close`, parseURL(t, "https://test.com/test/"), true, false)
	require.Nil(t, err, "could not parse unsafe request")
	require.Contains(t, string(request.UnsafeRawBytes), "GET /test/manager/html", "Could not parse unsafe method request path correctly")

	request, err = Parse(`GET ?a=b HTTP/1.1
	Host: {{Hostname}}
	Origin: {{BaseURL}}`, parseURL(t, "https://test.com/test.js"), true, false)
	require.Nil(t, err, "could not parse unsafe request")
	require.Contains(t, string(request.UnsafeRawBytes), "GET /test.js?a=b", "Could not parse unsafe method request path correctly")
}

func TestParseUnsafeRequestStripsLeadingAnnotations(t *testing.T) {
	request, err := Parse(`@Host: honey.scanme.sh
GET /foo HTTP/1.1
Host: {{Hostname}}
Connection: close`, parseURL(t, "http://scanme.sh"), true, false)
	require.Nil(t, err, "could not parse unsafe request with annotation")
	require.Contains(t, string(request.UnsafeRawBytes), "GET /foo HTTP/1.1", "unsafe request line should be preserved")
	require.NotContains(t, string(request.UnsafeRawBytes), "@Host:", "annotation lines must not be present in unsafe raw bytes")
}

func TestTryFillCustomHeaders(t *testing.T) {
	testValue := "GET /manager/html HTTP/1.1\r\nHost: Test\r\n"
	expected := "GET /test/manager/html HTTP/1.1\r\nHost: Test\r\ntest: test\r\n"
	request, err := Parse(testValue, parseURL(t, "https://test.com/test/"), true, false)
	require.Nil(t, err, "could not parse unsafe request")
	err = request.TryFillCustomHeaders([]string{"test: test"})
	require.Nil(t, err, "could not add custom headers")
	require.Equal(t, expected, string(request.UnsafeRawBytes), "actual value and expected value are different")
}

func TestDisableMergePath(t *testing.T) {
	request, err := Parse(` GET /api/v1/id=123 HTTP/1.1
	Host: {{Hostname}}`, parseURL(t, "https://example.com/api/v1/user"), false, true)
	require.Nil(t, err, "could not parse GET request with disable merge path")
	require.Equal(t, "https://example.com/api/v1/id=123", request.FullURL, "Could not parse request url with disable merge path correctly")

	request, err = Parse(` GET /api/v1/id=123 HTTP/1.1
	Host: {{Hostname}}`, parseURL(t, "https://example.com/api/v1/user"), false, false)
	require.Nil(t, err, "could not parse GET request with merge path")
	require.Equal(t, "https://example.com/api/v1/user/api/v1/id=123", request.FullURL, "Could not parse request url with merge path correctly")

}

func TestUnsafeWithFullURL(t *testing.T) {
	// Absolute-form request line (RFC 7230 Section 5.3.2) must reach the wire
	// verbatim in unsafe mode. See https://github.com/projectdiscovery/nuclei/issues/7382.
	request, err := Parse(`GET http://127.0.0.1/foo HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0
Connection: close`, parseURL(t, "http://httpbin.org/bar"), true, true)
	require.Nil(t, err, "could not parse unsafe request with full URL")
	require.Equal(t, "/foo", request.Path, "Path field should hold the relative component for downstream bookkeeping")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://127.0.0.1/foo HTTP/1.1", "UnsafeRawBytes should preserve the absolute URI")
}

func TestUnsafeWithFullURLAndPath(t *testing.T) {
	// Even when the target URL has a non-root path, an explicit absolute URI in
	// the request line should not be merged with it. The user has fully
	// specified the request target.
	request, err := Parse(`GET http://127.0.0.1/foo HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0
Connection: close`, parseURL(t, "http://httpbin.org/bar"), true, false)
	require.Nil(t, err, "could not parse unsafe request with full URL and path merge")
	require.Equal(t, "/foo", request.Path, "Path field should hold the relative component from the absolute URI, not the merged target path")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://127.0.0.1/foo HTTP/1.1", "UnsafeRawBytes should preserve the absolute URI without path automerge")
}

func TestUnsafeWithFullURLAndQueryParams(t *testing.T) {
	request, err := Parse(`GET http://127.0.0.1/foo?id=123&name=test HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0
Connection: close`, parseURL(t, "http://httpbin.org/bar"), true, true)
	require.Nil(t, err, "could not parse unsafe request with full URL and query params")
	require.Equal(t, "/foo?id=123&name=test", request.Path, "Path field should hold relative component with query params")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://127.0.0.1/foo?id=123&name=test HTTP/1.1", "UnsafeRawBytes should preserve the absolute URI with query params")
}

func TestUnsafeWithHTTPSFullURL(t *testing.T) {
	request, err := Parse(`GET https://secure.example.com/api/v1/users HTTP/1.1
Host: {{Hostname}}
Authorization: Bearer token123
Connection: close`, parseURL(t, "https://target.com/test"), true, true)
	require.Nil(t, err, "could not parse unsafe request with HTTPS full URL")
	require.Equal(t, "/api/v1/users", request.Path, "Path field should hold relative component from HTTPS full URL")
	require.Contains(t, string(request.UnsafeRawBytes), "GET https://secure.example.com/api/v1/users HTTP/1.1", "UnsafeRawBytes should preserve the HTTPS absolute URI")
}

func TestUnsafeWithFullURLRootPath(t *testing.T) {
	request, err := Parse(`GET http://example.com/ HTTP/1.1
Host: {{Hostname}}
Connection: close`, parseURL(t, "http://target.com/api"), true, true)
	require.Nil(t, err, "could not parse unsafe request with full URL root path")
	require.Equal(t, "/", request.Path, "Path field should hold the relative root from the absolute URI")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://example.com/ HTTP/1.1", "UnsafeRawBytes should preserve the absolute URI with root path")

	request, err = Parse(`GET http://example.com/ HTTP/1.1
Host: {{Hostname}}
Connection: close`, parseURL(t, "http://target.com/api"), true, false)
	require.Nil(t, err, "could not parse unsafe request with full URL root path and merge")
	require.Equal(t, "/", request.Path, "Path field should hold the relative root regardless of automerge")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://example.com/ HTTP/1.1", "UnsafeRawBytes should preserve the absolute URI even with automerge enabled")
}

// TestUnsafeWithFullURLAndPort reproduces the scenario from
// https://github.com/projectdiscovery/nuclei/issues/7382 where the request
// line contains an absolute URI with an explicit port. The scheme, host, and
// port must all reach the wire intact.
func TestUnsafeWithFullURLAndPort(t *testing.T) {
	request, err := Parse(`GET http://example.com:80/foo HTTP/1.1
Host: 127.0.0.1`, parseURL(t, "http://127.0.0.1:8000"), true, false)
	require.Nil(t, err, "could not parse unsafe request with full URL containing port")
	require.Equal(t, "/foo", request.Path, "Path field should hold relative component from absolute URI with port")
	require.Contains(t, string(request.UnsafeRawBytes), "GET http://example.com:80/foo HTTP/1.1", "UnsafeRawBytes should preserve scheme, host, and port verbatim")
}

func TestSafeWithFullURL(t *testing.T) {
	// Verify that safe mode still works correctly with full URLs (existing behavior)
	request, err := Parse(`GET http://example.com/api/users HTTP/1.1
Host: {{Hostname}}
Connection: close`, parseURL(t, "http://target.com/v1"), false, true)
	require.Nil(t, err, "could not parse safe request with full URL")
	require.Equal(t, "/api/users", request.Path, "Could not extract path from full URL in safe mode")
	require.Equal(t, "http://target.com/api/users", request.FullURL, "Could not build correct FullURL in safe mode")
}

func parseURL(t *testing.T, inputurl string) *urlutil.URL {
	urlx, err := urlutil.Parse(inputurl)
	if err != nil {
		t.Fatalf("failed to parse url %v", urlx)
	}
	return urlx
}
