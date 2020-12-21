package raw

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
)

// Request defines a HTTP raw request structure
type Request struct {
	Method  string
	Path    string
	Data    string
	Headers map[string]string
}

// Parse parses the raw request as supplied by the user
func Parse(request string, unsafe bool) (*Request, error) {
	reader := bufio.NewReader(strings.NewReader(request))

	rawRequest := Request{
		Headers: make(map[string]string),
	}

	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %s", err)
	}

	parts := strings.Split(s, " ")

	//nolint:gomnd // this is not a magic number
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	// Accepts all malformed headers
	var key, value string
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			break
		}

		//nolint:gomnd // this is not a magic number
		p := strings.SplitN(line, ":", 2)
		key = p[0]
		if len(p) > 1 {
			value = p[1]
		}

		// in case of unsafe requests multiple headers should be accepted
		// therefore use the full line as key
		_, found := rawRequest.Headers[key]
		if unsafe && found {
			rawRequest.Headers[line] = ""
		} else {
			rawRequest.Headers[key] = value
		}
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if !unsafe && strings.HasPrefix(parts[1], "http") {
		parsed, parseErr := url.Parse(parts[1])
		if parseErr != nil {
			return nil, fmt.Errorf("could not parse request URL: %s", parseErr)
		}

		rawRequest.Path = parts[1]
		rawRequest.Headers["Host"] = parsed.Host
	} else {
		rawRequest.Path = parts[1]
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}
	rawRequest.Data = string(b)
	return &rawRequest, nil
}

// URL returns the full URL for a raw request based on provided metadata
func (r *Request) URL(BaseURL string) (string, error) {
	parsed, err := url.Parse(BaseURL)
	if err != nil {
		return "", err
	}

	var hostURL string
	if r.Headers["Host"] == "" {
		hostURL = parsed.Host
	} else {
		hostURL = r.Headers["Host"]
	}

	if r.Path == "" {
		r.Path = parsed.Path
	} else if strings.HasPrefix(r.Path, "?") {
		r.Path = fmt.Sprintf("%s%s", parsed.Path, r.Path)
	}

	builder := &strings.Builder{}
	builder.WriteString(parsed.Scheme)
	builder.WriteString("://")
	builder.WriteString(strings.TrimSpace(hostURL))
	builder.WriteString(r.Path)
	URL := builder.String()
	return URL, nil
}
