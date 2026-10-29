package engine

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddResponseVariables(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Add("X-Custom", "a")
	resp.Header.Add("X-Custom", "b")
	resp.Header.Add("Set-Cookie", "SessionID=abc; Path=/")
	resp.Header.Add("Set-Cookie", "theme=dark; Path=/")

	data := make(map[string]interface{})
	addResponseVariables(data, resp, nil)

	require.Equal(t, "text/plain; charset=utf-8", data["content_type"])
	require.Equal(t, "a b", data["x_custom"])
	require.Equal(t, "abc", data["sessionid"])
	require.Equal(t, "dark", data["theme"])
	require.NotContains(t, data, "header")
}

func TestAddResponseVariablesNil(t *testing.T) {
	data := make(map[string]interface{})
	addResponseVariables(data, nil, nil)
	require.Empty(t, data)
}

func TestAddResponseVariablesCollisions(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Status-Code", "999")
	resp.Header.Set("Data", "spoofed")
	resp.Header.Set("Host", "evil.example")
	resp.Header.Set("Duration-1", "0")
	resp.Header.Set("IP", "6.6.6.6")
	resp.Header.Set("Path", "/spoofed")
	resp.Header.Set("Request", "spoofed")
	resp.Header.Set("Error", "spoofed")
	resp.Header.Set("X-Action", "from header")
	resp.Header.Add("Set-Cookie", "header=spoofed; Path=/")
	resp.Header.Add("Set-Cookie", "x_token=cookie; Path=/")
	resp.Header.Set("X-Token", "header")
	// both names normalize to x_dup; sorted order makes the result stable
	resp.Header["X-Dup"] = []string{"dash"}
	resp.Header["X_dup"] = []string{"underscore"}

	data := map[string]interface{}{
		"header":      "real headers",
		"status_code": "200",
		"x_action":    "from action",
	}
	addResponseVariables(data, resp, nil)

	require.Equal(t, "real headers", data["header"])
	require.Equal(t, "200", data["status_code"])
	require.Equal(t, "from action", data["x_action"])
	require.NotContains(t, data, "data")
	require.NotContains(t, data, "host")
	require.NotContains(t, data, "duration_1")
	for _, key := range []string{"ip", "path", "request", "error"} {
		require.NotContains(t, data, key)
	}
	require.Equal(t, "header", data["x_token"])
	require.Equal(t, "underscore", data["x_dup"])
}

func TestAddResponseVariablesBrowserCookies(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Add("Set-Cookie", "theme=dark; Path=/")
	browserCookies := []*http.Cookie{
		{Name: "SessID", Value: "abc"},
		{Name: "theme", Value: "light"},
		{Name: "data", Value: "spoofed"},
	}

	data := make(map[string]interface{})
	addResponseVariables(data, resp, browserCookies)

	require.Equal(t, "abc", data["sessid"])
	require.Equal(t, "dark", data["theme"])
	require.NotContains(t, data, "data")
}

func TestCookieMatchesHost(t *testing.T) {
	require.True(t, cookieMatchesHost("example.com", "example.com"))
	require.False(t, cookieMatchesHost("example.com", "sub.example.com"))
	require.True(t, cookieMatchesHost(".example.com", "example.com"))
	require.True(t, cookieMatchesHost(".example.com", "sub.example.com"))
	require.False(t, cookieMatchesHost(".example.com", "badexample.com"))
	require.False(t, cookieMatchesHost("other.com", "example.com"))
	require.True(t, cookieMatchesHost("127.0.0.1", "127.0.0.1"))
}
