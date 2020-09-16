package http

import (
	"net/http"
)

// setHeader sets a headers only if it wasn't already by the user
func setHeader(req *http.Request, name, value string) {
	if req.Header.Get(name) == "" {
		req.Header.Set(name, value)
	}
}
