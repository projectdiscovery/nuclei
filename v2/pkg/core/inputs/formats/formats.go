package formats

import (
	"bufio"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

// RawRequestCallback is a callback function for discovered raw requests
type RawRequestCallback func(request *RawRequest) bool

// Format is an interface implemented by all input formats
type Format interface {
	// Parse parses the input and calls the provided callback
	// function for each RawRequest it discovers.
	Parse(input string, resultsCb RawRequestCallback) error
}

// RawRequest contains a raw HTTP request parsed from different
// input formats.
type RawRequest struct {
	// URL is the URL of the raw request
	URL string `json:"url"`
	// Headers contains the headers of the raw request
	Headers map[string]string `json:"headers"`
	// Body is the body of the raw request
	Body string `json:"body"`
	// Method is the method of the raw request
	Method string `json:"method"`
	// Raw is the raw request
	Raw string `json:"raw"`
}

// ID returns a unique id/hash for raw request
func (r *RawRequest) ID() string {
	var builder strings.Builder
	builder.WriteString(r.Method)
	builder.WriteString(r.URL)
	value := builder.String()
	return value
}

// Request returns a retryablehttp request from the raw request
func (r *RawRequest) Request() (*retryablehttp.Request, error) {
	req, err := retryablehttp.NewRequest(r.Method, r.URL, strings.NewReader(r.Body))
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// ParseRawRequest parses a raw request from a string
func ParseRawRequest(raw, body, URL string) (*RawRequest, error) {
	parsedRequest, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse raw request")
	}

	headers := make(map[string]string)
	for k, v := range parsedRequest.Header {
		headers[k] = strings.Join(v, " ")
	}

	return &RawRequest{
		URL:     URL,
		Headers: headers,
		Body:    body,
		Method:  parsedRequest.Method,
		Raw:     raw,
	}, nil
}
