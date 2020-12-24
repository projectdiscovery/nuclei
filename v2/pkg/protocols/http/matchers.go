package http

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// responseToDSLMap converts a HTTP response to a map for use in DSL matching
func responseToDSLMap(resp *http.Response, body, headers string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, len(extra)+6+len(resp.Header)+len(resp.Cookies()))
	for k, v := range extra {
		data[k] = v
	}

	data["content_length"] = resp.ContentLength
	data["status_code"] = resp.StatusCode

	data["body"] = body
	for _, cookie := range resp.Cookies() {
		data[cookie.Name] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		data[k] = strings.Join(v, " ")
	}
	data["header"] = headers
	data["all_headers"] = headers

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		rawString := string(r)
		data["raw"] = rawString
		data["all"] = rawString
	}
	data["duration"] = duration.Seconds()
	return data
}
