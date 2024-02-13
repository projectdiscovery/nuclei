package types

import (
	"encoding/json"
	"fmt"

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
