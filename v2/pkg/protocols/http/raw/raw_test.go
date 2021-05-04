package raw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRawRequestWithPort(t *testing.T) {
	request, err := Parse(`GET /gg/phpinfo.php HTTP/1.1
Host: {{Hostname}}:123
Origin: {{BaseURL}}
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.9`, "https://example.com:8080", false)
	require.Nil(t, err, "could not parse GET request")
	require.Equal(t, "https://example.com:8080/gg/phpinfo.php", request.FullURL, "Could not parse request url correctly")
	require.Equal(t, "/gg/phpinfo.php", request.Path, "Could not parse request path correctly")

	t.Run("path-suffix", func(t *testing.T) {
		request, err := Parse(`GET /hello HTTP/1.1
Host: {{Hostname}}`, "https://example.com:8080/test", false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test/hello", request.FullURL, "Could not parse request url correctly")
	})

	t.Run("query-values", func(t *testing.T) {
		request, err := Parse(`GET ?username=test&password=test HTTP/1.1
Host: {{Hostname}}:123`, "https://example.com:8080/test", false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test?username=test&password=test", request.FullURL, "Could not parse request url correctly")

		request, err = Parse(`GET ?username=test&password=test HTTP/1.1
Host: {{Hostname}}:123`, "https://example.com:8080/test/", false)
		require.Nil(t, err, "could not parse GET request")
		require.Equal(t, "https://example.com:8080/test/?username=test&password=test", request.FullURL, "Could not parse request url correctly")

		request, err = Parse(`GET /?username=test&password=test HTTP/1.1
		Host: {{Hostname}}:123`, "https://example.com:8080/test/", false)
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
Connection: close`, "https://test.com", false)
	require.Nil(t, err, "could not parse GET request")
	require.Equal(t, "GET", request.Method, "Could not parse GET method request correctly")
	require.Equal(t, "/manager/html", request.Path, "Could not parse request path correctly")

	request, err = Parse(`POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Connection: close

username=admin&password=login`, "https://test.com", false)
	require.Nil(t, err, "could not parse POST request")
	require.Equal(t, "POST", request.Method, "Could not parse POST method request correctly")
	require.Equal(t, "username=admin&password=login", request.Data, "Could not parse request data correctly")
}
