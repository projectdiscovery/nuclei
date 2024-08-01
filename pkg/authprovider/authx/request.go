package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

func unwrapRequest(rt any) *http.Request {
	switch v := rt.(type) {
	case *http.Request:
		// return it as is.
		return v
	case *retryablehttp.Request:
		// return its embedded *http.Request.
		return v.Request
	default:
		return nil
	}
}
