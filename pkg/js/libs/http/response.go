package http

import (
	"net/http"
	"strings"
)

type (
	// Response is an HTTP response returned by Client methods.
	// @example
	// ```javascript
	// const http = require('nuclei/http');
	// const resp = http.Get('https://example.com');
	// log(resp.StatusCode);
	// log(resp.GetHeader('Content-Type'));
	// log(resp.Proto);
	// ```
	Response struct {
		StatusCode int
		// Proto is the protocol of the response, e.g. "HTTP/1.1" or "HTTP/2.0".
		Proto   string
		URL     string
		Body    string
		Headers map[string]string

		header http.Header
	}
)

// GetHeader returns the first value for a header (case-insensitive), or "".
// @example
// ```javascript
// const http = require('nuclei/http');
// const resp = http.Get('https://example.com');
// const ct = resp.GetHeader('content-type');
// ```
func (r *Response) GetHeader(name string) string {
	if r == nil {
		return ""
	}
	if r.header != nil {
		return r.header.Get(name)
	}
	if r.Headers == nil {
		return ""
	}
	if v, ok := r.Headers[name]; ok {
		return v
	}
	// case-insensitive fallback on flattened map
	lower := strings.ToLower(name)
	for k, v := range r.Headers {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return ""
}
