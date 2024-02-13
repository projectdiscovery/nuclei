package types

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"strings"

	"github.com/projectdiscovery/utils/conversion"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	_ json.Marshaler   = &RequestResponse{}
	_ json.Unmarshaler = &RequestResponse{}
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
}

// MarshalJSON marshals the request response to json
func (rr RequestResponse) MarshalJSON() ([]byte, error) {
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
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	urlStr, ok := m["url"]
	if !ok {
		return fmt.Errorf("missing url in request response")
	}
	parsed, err := urlutil.ParseAbsoluteURL(string(urlStr), false)
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

// ParseRawRequest parses a raw request from a string
// and returns the request and response object
// Note: it currently does not parse response
func ParseRawRequest(raw string) (rr *RequestResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
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
	fmt.Println(hostLine)

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
	rr.Request.Body = conversion.String(buff.Bytes())

	// set raw request
	rr.Request.Raw = raw
	return rr, nil
}
