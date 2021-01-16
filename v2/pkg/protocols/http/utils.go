package http

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/rawhttp"
)

// headersToString converts http headers to string
func headersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)

			if i != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}

// dump creates a dump of the http request in form of a byte slice
func dump(req *generatedRequest, reqURL string) ([]byte, error) {
	if req.request != nil {
		// Create a copy on the fly of the request body - ignore errors
		bodyBytes, _ := req.request.BodyBytes()
		req.request.Request.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		return httputil.DumpRequestOut(req.request.Request, true)
	}
	return rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(req.rawRequest.Data)))
}

// handleDecompression if the user specified a custom encoding (as golang transport doesn't do this automatically)
func handleDecompression(r *generatedRequest, bodyOrig []byte) (bodyDec []byte, err error) {
	if r.request == nil {
		return bodyOrig, nil
	}

	encodingHeader := strings.TrimSpace(strings.ToLower(r.request.Header.Get("Accept-Encoding")))
	if encodingHeader == "gzip" || encodingHeader == "gzip, deflate" {
		gzipreader, err := gzip.NewReader(bytes.NewReader(bodyOrig))
		if err != nil {
			return bodyDec, err
		}
		defer gzipreader.Close()

		bodyDec, err = ioutil.ReadAll(gzipreader)
		if err != nil {
			return bodyDec, err
		}
		return bodyDec, nil
	}
	return bodyOrig, nil
}
