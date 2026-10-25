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
	addResponseVariables(data, resp)

	require.Equal(t, "text/plain; charset=utf-8", data["content_type"])
	require.Equal(t, "a b", data["x_custom"])
	require.Equal(t, "abc", data["sessionid"])
	require.Equal(t, "dark", data["theme"])
	require.NotContains(t, data, "header")
}

func TestAddResponseVariablesNil(t *testing.T) {
	data := make(map[string]interface{})
	addResponseVariables(data, nil)
	require.Empty(t, data)
}

func TestAddResponseVariablesCollisions(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Status-Code", "999")
	resp.Header.Set("Data", "spoofed")
	resp.Header.Set("Host", "evil.example")
	resp.Header.Set("Duration-1", "0")
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
	addResponseVariables(data, resp)

	require.Equal(t, "real headers", data["header"])
	require.Equal(t, "200", data["status_code"])
	require.Equal(t, "from action", data["x_action"])
	require.NotContains(t, data, "data")
	require.NotContains(t, data, "host")
	require.NotContains(t, data, "duration_1")
	require.Equal(t, "header", data["x_token"])
	require.Equal(t, "underscore", data["x_dup"])
}
