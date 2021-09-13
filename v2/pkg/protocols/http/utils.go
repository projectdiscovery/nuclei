package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
	"github.com/projectdiscovery/rawhttp"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// dumpResponseWithRedirectChain dumps a http response with the
// complete http redirect chain.
//
// It preserves the order in which responses were given to requests
// and returns the data to the user for matching and viewing in that order.
//
// Inspired from - https://github.com/ffuf/ffuf/issues/324#issuecomment-719858923
func dumpResponseWithRedirectChain(resp *http.Response, body []byte) ([]byte, error) {
	redirects := []string{}
	respData, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, err
	}
	redirectChain := &bytes.Buffer{}

	redirectChain.WriteString(tostring.UnsafeToString(respData))
	redirectChain.Write(body)
	redirects = append(redirects, redirectChain.String())
	redirectChain.Reset()

	var redirectResp *http.Response
	if resp != nil && resp.Request != nil {
		redirectResp = resp.Request.Response
	}
	for redirectResp != nil {
		var body []byte

		respData, err := httputil.DumpResponse(redirectResp, false)
		if err != nil {
			break
		}
		if redirectResp.Body != nil {
			body, _ = ioutil.ReadAll(redirectResp.Body)
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
	return rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), ioutil.NopCloser(strings.NewReader(req.rawRequest.Data)), rawhttp.Options{CustomHeaders: req.rawRequest.UnsafeHeaders, CustomRawBytes: req.rawRequest.UnsafeRawBytes})
}

// handleDecompression if the user specified a custom encoding (as golang transport doesn't do this automatically)
func handleDecompression(resp *http.Response, bodyOrig []byte) (bodyDec []byte, err error) {
	if resp == nil {
		return bodyOrig, nil
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(bodyOrig))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(bodyOrig))
	default:
		return bodyOrig, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	bodyDec, err = ioutil.ReadAll(reader)
	if err != nil {
		return bodyOrig, err
	}
	return bodyDec, nil
}

// decodegbk converts GBK to UTF-8
func decodegbk(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}
