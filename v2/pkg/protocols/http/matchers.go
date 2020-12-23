package http

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// responseToDSLMap converts a HTTP response to a map for use in DSL matching
func responseToDSLMap(resp *http.Response, body, headers string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, len(extra)+6+len(resp.Header))
	for k, v := range extra {
		data[k] = v
	}

	data["content_length"] = resp.ContentLength
	data["status_code"] = resp.StatusCode

	data["body"] = body
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		data[k] = strings.Join(v, " ")
	}
	data["headers"] = headers

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		data["raw"] = string(r)
	}
	data["duration"] = duration.Seconds()
	return data
}
