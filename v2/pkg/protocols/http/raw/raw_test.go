package raw

import (
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

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

func parseURL(t *testing.T, inputurl string) *urlutil.URL {
	urlx, err := urlutil.Parse(inputurl)
	if err != nil {
		t.Fatalf("failed to parse url %v", urlx)
	}
	return urlx
}
