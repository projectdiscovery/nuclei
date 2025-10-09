package types

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/textproto"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	"github.com/projectdiscovery/utils/conversion"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	_ json.JSONCodec = &RequestResponse{}
)

// RequestResponse is a struct containing request and response
// obtained from one of the input formats.
// this struct can be considered as pd standard for request and response
type RequestResponse struct {
	// Timestamp is the timestamp of the request
	// Timestamp string `json:"timestamp"`
	// URL is the URL of the request
	URL urlutil.URL `json:"url"`
	// Request is the request of the request
	Request *HttpRequest `json:"request"`
	// Response is the response of the request
	Response *HttpResponse `json:"response"`

	// unexported / internal fields
	// lazy build request
	req    *retryablehttp.Request `json:"-"`
	reqErr error                  `json:"-"`
	once   sync.Once              `json:"-"`
}

// Clone clones the request response
func (rr *RequestResponse) Clone() *RequestResponse {
	cloned := &RequestResponse{
		URL: *rr.URL.Clone(),
	}
	if rr.Request != nil {
		cloned.Request = rr.Request.Clone()
	}
	if rr.Response != nil {
		cloned.Response = rr.Response.Clone()
	}
	return cloned
}

// BuildRequest builds a retryablehttp request from the request response
func (rr *RequestResponse) BuildRequest() (*retryablehttp.Request, error) {
	rr.once.Do(func() {
		urlx := rr.URL.Clone()
		var body io.Reader = nil
		if rr.Request.Body != "" {
			body = strings.NewReader(rr.Request.Body)
		}
		req, err := retryablehttp.NewRequestFromURL(rr.Request.Method, urlx, body)
		if err != nil {
			rr.reqErr = fmt.Errorf("could not create request: %s", err)
			return
		}
		rr.Request.Headers.Iterate(func(k, v string) bool {
			req.Header.Add(k, v)
			return true
		})
		if req.Header.Get("User-Agent") == "" {
			userAgent := useragent.PickRandom()
			req.Header.Set("User-Agent", userAgent.Raw)
		}
		rr.req = req
	})
	return rr.req, rr.reqErr
}

// To be implemented in the future
// func (rr *RequestResponse) BuildUnsafeRequest()

// ID returns a unique id/hash for request response
func (rr *RequestResponse) ID() string {
	var buff bytes.Buffer
	buff.WriteString(rr.URL.String())
	if rr.Request != nil {
		buff.WriteString(rr.Request.ID())
	}
	if rr.Response != nil {
		buff.WriteString(rr.Response.ID())
	}
	val := sha256.Sum256(buff.Bytes())
	return string(val[:])
}

// MarshalJSON marshals the request response to json
func (rr *RequestResponse) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["url"] = rr.URL.String()
	reqBin, err := json.Marshal(rr.Request)
	if err != nil {
		return nil, err
	}
	m["request"] = reqBin
	respBin, err := json.Marshal(rr.Response)
	if err != nil {
		return nil, err
	}
	m["response"] = respBin
	return json.Marshal(m)
}

// UnmarshalJSON unmarshals the request response from json
func (rr *RequestResponse) UnmarshalJSON(data []byte) error {
	var m map[string]json.Message
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	urlStrRaw, ok := m["url"]
	if !ok {
		return fmt.Errorf("missing url in request response")
	}
	var urlStr string
	if err := json.Unmarshal(urlStrRaw, &urlStr); err != nil {
		return err
	}
	parsed, err := urlutil.ParseAbsoluteURL(urlStr, false)
	if err != nil {
		return err
	}
	rr.URL = *parsed

	reqBin, ok := m["request"]
	if ok {
		var req HttpRequest
		if err := json.Unmarshal(reqBin, &req); err != nil {
			return err
		}
		rr.Request = &req
	}

	respBin, ok := m["response"]
	if ok {
		var resp HttpResponse
		if err := json.Unmarshal(respBin, &resp); err != nil {
			return err
		}
		rr.Response = &resp
	}
	return nil
}

// HttpRequest is a struct containing the http request
type HttpRequest struct {
	// method of the request
	Method string `json:"method"`
	// headers of the request
	Headers mapsutil.OrderedMap[string, string] `json:"headers"`
	// body of the request
	Body string `json:"body"`
	// raw request (includes everything including method, headers, body, etc)
	Raw string `json:"raw"`
}

// ID returns a unique id/hash for raw request
func (hr *HttpRequest) ID() string {
	val := sha256.Sum256([]byte(hr.Raw))
	return string(val[:])
}

// Clone clones the request
func (hr *HttpRequest) Clone() *HttpRequest {
	return &HttpRequest{
		Method:  hr.Method,
		Headers: hr.Headers.Clone(),
		Body:    hr.Body,
		Raw:     hr.Raw,
	}
}

type HttpResponse struct {
	// status code of the response
	StatusCode int `json:"status_code"`
	// headers of the response
	Headers mapsutil.OrderedMap[string, string] `json:"headers"`
	// body of the response
	Body string `json:"body"`
	// raw response (includes everything including status code, headers, body, etc)
	Raw string `json:"raw"`
}

// Id returns a unique id/hash for raw response
func (hr *HttpResponse) ID() string {
	val := sha256.Sum256([]byte(hr.Raw))
	return string(val[:])
}

// Clone clones the response
func (hr *HttpResponse) Clone() *HttpResponse {
	return &HttpResponse{
		StatusCode: hr.StatusCode,
		Headers:    hr.Headers.Clone(),
		Body:       hr.Body,
		Raw:        hr.Raw,
	}
}

// ParseRawRequest parses a raw request from a string
// and returns the request and response object
// Note: it currently does not parse response and is meant to be added manually since its a optional field
func ParseRawRequest(raw string) (rr *RequestResponse, err error) {
	protoReader := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
	methodLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read method line: %s", err)
	}
	rr = &RequestResponse{
		Request: &HttpRequest{},
	}
	/// must contain at least 3 parts
	parts := strings.Split(methodLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid method line: %s", methodLine)
	}
	method := parts[0]
	rr.Request.Method = method

	// parse relative url
	urlx, err := urlutil.ParseRawRelativePath(parts[1], true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %s", err)
	}
	rr.URL = *urlx

	// parse host line
	hostLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read host line: %s", err)
	}
	sep := strings.Index(hostLine, ":")
	if sep <= 0 || sep >= len(hostLine)-1 {
		return nil, fmt.Errorf("invalid host line: %s", hostLine)
	}
	hostLine = hostLine[sep+2:]
	rr.URL.Host = hostLine

	// parse headers
	rr.Request.Headers = mapsutil.NewOrderedMap[string, string]()
	for {
		line, err := protoReader.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read header line: %s", err)
		}
		if line == "" {
			// end of headers next is body
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header line: %s", line)
		}
		rr.Request.Headers.Set(parts[0], parts[1][1:])
	}

	// parse body
	rr.Request.Body = ""
	var buff bytes.Buffer
	_, err = buff.ReadFrom(protoReader.R)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read body: %s", err)
	}
	if buff.Len() > 0 {
		// yaml may include trailing newlines
		// remove them if present
		bin := buff.Bytes()
		if bin[len(bin)-1] == '\n' {
			bin = bin[:len(bin)-1]
		}
		if bin[len(bin)-1] == '\r' || bin[len(bin)-1] == '\n' {
			bin = bin[:len(bin)-1]
		}
		rr.Request.Body = conversion.String(bin)
	}

	// set raw request
	rr.Request.Raw = raw
	return rr, nil
}

// ParseRawRequestWithURL parses a raw request from a string with given url
func ParseRawRequestWithURL(raw, url string) (rr *RequestResponse, err error) {
	rr, err = ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}
	urlx, err := urlutil.ParseAbsoluteURL(url, false)
	if err != nil {
		return nil, err
	}
	rr.URL = *urlx
	return rr, nil
}
