package engine

import (
	"maps"
	"net/http"
	"slices"
	"strings"
)

// reservedResponseKeys are the event fields that the headless protocol owns.
// A response header or cookie that normalizes to one of them is dropped, so a
// target cannot spoof them (the HTTP protocol also lets its own fields win).
var reservedResponseKeys = map[string]struct{}{
	"template-id":   {},
	"template-info": {},
	"template-path": {},
	"host":          {},
	"matched":       {},
	"type":          {},
	"req":           {},
	"resp":          {},
	"body":          {},
	"data":          {},
	"header":        {},
	"all_headers":   {},
	"status_code":   {},
	"history":       {},
	"duration":      {},
	// read by the result event, so a target must not set them
	"ip":      {},
	"path":    {},
	"request": {},
	"error":   {},
}

// addResponseVariables exposes response headers and cookies as DSL variables
// (same normalization as the HTTP protocol).
// Header names are lowercased with "-" replaced by "_", e.g. Content-Type -> content_type.
// Cookie names are lowercased as-is.
// browserCookies are the cookies the browser holds for the page, as the
// browser does not report Set-Cookie in intercepted response headers. A
// Set-Cookie of the response wins over a browser cookie, and a header wins
// over a cookie of the same name. Headers that normalize to the same name are
// applied in sorted order, so the result is deterministic. Keys already in
// data and reserved protocol keys are never overwritten.
func addResponseVariables(data map[string]interface{}, resp *http.Response, browserCookies []*http.Cookie) {
	if resp == nil {
		return
	}
	vars := make(map[string]string)
	for _, cookie := range browserCookies {
		vars[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for _, cookie := range resp.Cookies() {
		vars[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for _, name := range slices.Sorted(maps.Keys(resp.Header)) {
		k := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
		vars[k] = strings.Join(resp.Header[name], " ")
	}
	for k, v := range vars {
		if _, ok := reservedResponseKeys[k]; ok || strings.HasPrefix(k, "duration_") {
			continue
		}
		if _, ok := data[k]; ok {
			continue
		}
		data[k] = v
	}
}
