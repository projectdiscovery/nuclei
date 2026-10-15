package engine

import (
	"net/http"
	"strings"
)

// addResponseVariables exposes response headers and cookies as DSL variables
// (same normalization as the HTTP protocol).
// Header names are lowercased with "-" replaced by "_", e.g. Content-Type -> content_type.
// Cookie names are lowercased as-is.
func addResponseVariables(data map[string]interface{}, resp *http.Response) {
	if resp == nil {
		return
	}
	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		data[k] = strings.Join(v, " ")
	}
}
