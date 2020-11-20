package requests

import (
	"bytes"
	"io/ioutil"
	"net/http/httputil"
	"strings"

	"github.com/projectdiscovery/rawhttp"
)

func Dump(req *HTTPRequest, reqURL string) ([]byte, error) {
	if req.Request != nil {
		// Create a copy on the fly of the request body - ignore errors
		bodyBytes, _ := req.Request.BodyBytes()
		req.Request.Request.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		return httputil.DumpRequest(req.Request.Request, true)
	}

	return rawhttp.DumpRequestRaw(req.RawRequest.Method, reqURL, req.RawRequest.Path, ExpandMapValues(req.RawRequest.Headers), ioutil.NopCloser(strings.NewReader(req.RawRequest.Data)))
}
