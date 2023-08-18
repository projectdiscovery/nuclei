package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type redirectedResponse struct {
	headers      []byte
	body         []byte
	fullResponse []byte
	resp         *http.Response
}

// dumpResponseWithRedirectChain dumps a http response with the
// complete http redirect chain.
//
// It preserves the order in which responses were given to requests
// and returns the data to the user for matching and viewing in that order.
//
// Inspired from - https://github.com/ffuf/ffuf/issues/324#issuecomment-719858923
func dumpResponseWithRedirectChain(resp *http.Response, body []byte) ([]redirectedResponse, error) {
	var response []redirectedResponse

	respData, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, err
	}
	respObj := redirectedResponse{
		headers:      respData,
		body:         body,
		resp:         resp,
		fullResponse: bytes.Join([][]byte{respData, body}, []byte{}),
	}
	if err := normalizeResponseBody(resp, &respObj); err != nil {
		return nil, err
	}
	response = append(response, respObj)

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
			body, _ = io.ReadAll(redirectResp.Body)
		}
		respObj := redirectedResponse{
			headers:      respData,
			body:         body,
			resp:         redirectResp,
			fullResponse: bytes.Join([][]byte{respData, body}, []byte{}),
		}
		if err := normalizeResponseBody(redirectResp, &respObj); err != nil {
			return nil, err
		}
		response = append(response, respObj)
		redirectResp = redirectResp.Request.Response
	}
	return response, nil
}

// normalizeResponseBody performs normalization on the http response object.
func normalizeResponseBody(resp *http.Response, response *redirectedResponse) error {
	var err error
	// net/http doesn't automatically decompress the response body if an
	// encoding has been specified by the user in the request so in case we have to
	// manually do it.
	dataOrig := response.body
	response.body, err = handleDecompression(resp, response.body)
	// in case of error use original data
	if err != nil {
		response.body = dataOrig
	}
	response.fullResponse = bytes.ReplaceAll(response.fullResponse, dataOrig, response.body)

	// Decode gbk response content-types
	// gb18030 supersedes gb2312
	responseContentType := resp.Header.Get("Content-Type")
	if isContentTypeGbk(responseContentType) {
		response.fullResponse, err = decodeGBK(response.fullResponse)
		if err != nil {
			return errors.Wrap(err, "could not gbk decode")
		}

		// the uncompressed body needs to be decoded to standard utf8
		response.body, err = decodeGBK(response.body)
		if err != nil {
			return errors.Wrap(err, "could not gbk decode")
		}
	}
	return nil
}

// dump creates a dump of the http request in form of a byte slice
func dump(req *generatedRequest, reqURL string) ([]byte, error) {
	if req.request != nil {
		return req.request.Dump()
	}
	rawHttpOptions := &rawhttp.Options{CustomHeaders: req.rawRequest.UnsafeHeaders, CustomRawBytes: req.rawRequest.UnsafeRawBytes}
	return rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), io.NopCloser(strings.NewReader(req.rawRequest.Data)), rawHttpOptions)
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

	bodyDec, err = io.ReadAll(reader)
	if err != nil {
		return bodyOrig, err
	}
	return bodyDec, nil
}

// decodeGBK converts GBK to UTF-8
func decodeGBK(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

// isContentTypeGbk checks if the content-type header is gbk
func isContentTypeGbk(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return stringsutil.ContainsAny(contentType, "gbk", "gb2312", "gb18030")
}

// if template contains more than 1 request and matchers require requestcondition from
// both requests , then we need to request for event from interactsh even if current request
// doesnot use interactsh url in it
func getInteractshURLsFromEvent(event map[string]interface{}) []string {
	interactshUrls := map[string]struct{}{}
	for k, v := range event {
		if strings.HasPrefix(k, "interactsh-url") {
			interactshUrls[types.ToString(v)] = struct{}{}
		}
	}
	return mapsutil.GetKeys(interactshUrls)
}
