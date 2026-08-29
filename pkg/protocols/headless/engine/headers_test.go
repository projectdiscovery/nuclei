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
