package http

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// rawRequest is a request structure used for making raw http requests
type rawRequest struct {
	Method  string
	Path    string
	Data    string
	Headers map[string]string
}

const baseURLVariable = "{{BaseURL}}"

// compileRawRequests returns a compiled version o fh
func (r *Request) compileRawRequests() (*CompiledRequest, error) {
	compiledRequest := &CompiledRequest{
		AtomicRequests: make([]*AtomicRequest, 0, len(r.Raw)),
	}
	for _, request := range r.Raw {
		rawRequest, err := r.parseRawRequest(request)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse raw request")
		}

		if strings.HasPrefix(rawRequest.Path, "/") {
			rawRequest.Path = baseURLVariable + rawRequest.Path
		} else if strings.HasPrefix(rawRequest.Path, "?") {
			rawRequest.Path = baseURLVariable + "/" + rawRequest.Path
		} else {
			rawRequest.Path = baseURLVariable
		}

		atomicRequest := AtomicRequest{
			Method:       rawRequest.Method,
			Redirects:    r.Redirects,
			MaxRedirects: r.MaxRedirects,
			Path:         rawRequest.Path,
			Headers:      rawRequest.Headers,
			Body:         rawRequest.Data,
		}
		fmt.Printf("%+v\n", atomicRequest)
	}
	return compiledRequest, nil
}

const (
	numFieldHeader    = 3
	numHeaderKeyValue = 2
)

// parseRawRequest parses the raw request as supplied by the user
func (r *Request) parseRawRequest(request string) (*rawRequest, error) {
	reader := bufio.NewReader(strings.NewReader(request))

	rawRequest := rawRequest{
		Headers: make(map[string]string),
	}

	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, errors.Wrap(err, "could not read request")
	}

	parts := strings.Split(s, " ")

	if len(parts) < numFieldHeader {
		return nil, errors.New("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", numHeaderKeyValue)
		if len(p) != numHeaderKeyValue {
			continue
		}

		if strings.EqualFold(p[0], "content-length") {
			continue
		}

		rawRequest.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if strings.HasPrefix(parts[1], "http") {
		parsed, parseErr := url.Parse(parts[1])
		if parseErr != nil {
			return nil, errors.Wrap(parseErr, "could not parse request URL")
		}

		rawRequest.Path = parts[1]
		rawRequest.Headers["Host"] = parsed.Host
	} else {
		rawRequest.Path = parts[1]
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrap(err, "could not read request body")
	}
	rawRequest.Data = string(b)
	return &rawRequest, nil
}
