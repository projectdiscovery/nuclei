package raw

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
)

// Request defines a basic HTTP raw request
type Request struct {
	FullURL string
	Method  string
	Path    string
	Data    string
	Headers map[string]string
}

// Parse parses the raw request as supplied by the user
func Parse(request, baseURL string, unsafe bool) (*Request, error) {
	reader := bufio.NewReader(strings.NewReader(request))
	rawRequest := &Request{
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
			rawRequest.Headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
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

	// If raw request doesn't have a Host header and/ path,
	// this will be generated from the parsed baseURL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %s", err)
	}

	var hostURL string
	if rawRequest.Headers["Host"] == "" {
		hostURL = parsedURL.Host
	} else {
		hostURL = rawRequest.Headers["Host"]
	}
	if strings.Contains(hostURL, ":") && strings.Contains(parsedURL.Host, ":") {
		parsedURL.Host, _, _ = net.SplitHostPort(parsedURL.Host)
	}

	if rawRequest.Path == "" {
		rawRequest.Path = parsedURL.Path
	} else if strings.HasPrefix(rawRequest.Path, "?") {
		rawRequest.Path = fmt.Sprintf("%s%s", parsedURL.Path, rawRequest.Path)
	}
	rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, strings.TrimSpace(hostURL), rawRequest.Path)

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}
	rawRequest.Data = string(b)
	return rawRequest, nil
}
