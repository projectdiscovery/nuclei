package raw

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/projectdiscovery/rawhttp/client"
)

// Request defines a basic HTTP raw request
type Request struct {
	FullURL        string
	Method         string
	Path           string
	Data           string
	Headers        map[string]string
	UnsafeHeaders  client.Headers
	UnsafeRawBytes []byte
}

// Parse parses the raw request as supplied by the user
func Parse(request, baseURL string, unsafe bool) (*Request, error) {
	rawRequest := &Request{
		Headers: make(map[string]string),
	}
	if unsafe {
		rawRequest.UnsafeRawBytes = []byte(request)
	}
	reader := bufio.NewReader(strings.NewReader(request))
	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %s", err)
	}

	parts := strings.Split(s, " ")
	if len(parts) < 3 && !unsafe {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	var mutlipartRequest bool
	// Accepts all malformed headers
	var key, value string
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			if readErr != io.EOF {
				break
			}
		}

		p := strings.SplitN(line, ":", 2)
		key = p[0]
		if len(p) > 1 {
			value = p[1]
		}
		if strings.Contains(key, "Content-Type") && strings.Contains(value, "multipart/") {
			mutlipartRequest = true
		}

		// in case of unsafe requests multiple headers should be accepted
		// therefore use the full line as key
		_, found := rawRequest.Headers[key]
		if unsafe {
			rawRequest.UnsafeHeaders = append(rawRequest.UnsafeHeaders, client.Header{Key: line})
		}

		if unsafe && found {
			rawRequest.Headers[line] = ""
		} else {
			rawRequest.Headers[key] = strings.TrimSpace(value)
		}
		if readErr == io.EOF {
			break
		}
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if !unsafe && strings.HasPrefix(parts[1], "http") {
		parsed, parseErr := url.Parse(parts[1])
		if parseErr != nil {
			return nil, fmt.Errorf("could not parse request URL: %s", parseErr)
		}

		rawRequest.Path = parsed.Path
		if _, ok := rawRequest.Headers["Host"]; !ok {
			rawRequest.Headers["Host"] = parsed.Host
		}
	} else if len(parts) > 1 {
		rawRequest.Path = parts[1]
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %s", err)
	}
	hostURL := parsedURL.Host
	if strings.HasSuffix(parsedURL.Path, "/") && strings.HasPrefix(rawRequest.Path, "/") {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	}
	if parsedURL.Path != rawRequest.Path {
		rawRequest.Path = fmt.Sprintf("%s%s", parsedURL.Path, rawRequest.Path)
	}
	if strings.HasSuffix(rawRequest.Path, "//") {
		rawRequest.Path = strings.TrimSuffix(rawRequest.Path, "/")
	}
	rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, strings.TrimSpace(hostURL), rawRequest.Path)

	// If raw request doesn't have a Host header and isn't marked unsafe,
	// this will generate the Host header from the parsed baseURL
	if !unsafe && rawRequest.Headers["Host"] == "" {
		rawRequest.Headers["Host"] = hostURL
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}
	rawRequest.Data = string(b)
	if !mutlipartRequest {
		rawRequest.Data = strings.TrimSuffix(rawRequest.Data, "\r\n")
	}
	return rawRequest, nil
}
