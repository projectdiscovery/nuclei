package http

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/rawhttp"
)

// dumpResponseWithRedirectChain dumps a http response with the
// complete http redirect chain.
//
// It preserves the order in which responses were given to requests
// and returns the data to the user for matching and viewing in that order.
//
// Inspired from - https://github.com/ffuf/ffuf/issues/324#issuecomment-719858923
func dumpResponseWithRedirectChain(resp *http.Response, body []byte) ([]byte, error) {
	redirectChain := &bytes.Buffer{}
	redirectResp := resp.Request.Response

	redirects := []string{}
	respData, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, err
	}
	redirectChain.WriteString(tostring.UnsafeToString(respData))
	redirectChain.Write(body)
	redirects = append(redirects, redirectChain.String())
	redirectChain.Reset()

	for redirectResp != nil {
		var body []byte

		respData, err := httputil.DumpResponse(redirectResp, false)
		if err != nil {
			break
		}
		redirectChain.WriteString(tostring.UnsafeToString(respData))
		if len(body) > 0 {
			redirectChain.WriteString(tostring.UnsafeToString(body))
		}
		redirects = append(redirects, redirectChain.String())
		redirectResp = redirectResp.Request.Response
		redirectChain.Reset()
	}

	for i := len(redirects) - 1; i >= 0; i-- {
		redirectChain.WriteString(redirects[i])
	}
	return redirectChain.Bytes(), nil
}

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
func handleDecompression(resp *http.Response, bodyOrig []byte) (bodyDec []byte, err error) {
	if resp == nil {
		return bodyOrig, nil
	}

	encodingHeader := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	if strings.Contains(encodingHeader, "gzip") {
		gzipreader, err := gzip.NewReader(bytes.NewReader(bodyOrig))
		if err != nil {
			return bodyOrig, err
		}
		defer gzipreader.Close()

		bodyDec, err = ioutil.ReadAll(gzipreader)
		if err != nil {
			return bodyOrig, err
		}
		return bodyDec, nil
	}
	return bodyOrig, nil
}
