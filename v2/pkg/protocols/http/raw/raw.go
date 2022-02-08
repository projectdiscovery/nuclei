package raw

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"path"
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

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %w", err)
	}

	if unsafe {
		rawRequest.UnsafeRawBytes = []byte(request)
	}
	reader := bufio.NewReader(strings.NewReader(request))
	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %w", err)
	}

	parts := strings.Split(s, " ")
	if len(parts) < 3 && !unsafe {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Check if we have also a path from the passed base URL and if yes,
	// append that to the unsafe request as well.
	if parsedURL.Path != "" && strings.HasPrefix(parts[1], "/") && parts[1] != parsedURL.Path {
		rawRequest.UnsafeRawBytes = fixUnsafeRequestPath(parsedURL, parts[1], rawRequest.UnsafeRawBytes)
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	var multiPartRequest bool
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
			multiPartRequest = true
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
			return nil, fmt.Errorf("could not parse request URL: %w", parseErr)
		}

		rawRequest.Path = parsed.Path
		if _, ok := rawRequest.Headers["Host"]; !ok {
			rawRequest.Headers["Host"] = parsed.Host
		}
	} else if len(parts) > 1 {
		rawRequest.Path = parts[1]
	}

	hostURL := parsedURL.Host
	if strings.HasSuffix(parsedURL.Path, "/") && strings.HasPrefix(rawRequest.Path, "/") {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	}

	if !unsafe {
		if parsedURL.Path != rawRequest.Path {
			rawRequest.Path = fmt.Sprintf("%s%s", parsedURL.Path, rawRequest.Path)
		}
		if strings.HasSuffix(rawRequest.Path, "//") {
			rawRequest.Path = strings.TrimSuffix(rawRequest.Path, "/")
		}
		rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, strings.TrimSpace(hostURL), rawRequest.Path)

		// If raw request doesn't have a Host header and isn't marked unsafe,
		// this will generate the Host header from the parsed baseURL
		if rawRequest.Headers["Host"] == "" {
			rawRequest.Headers["Host"] = hostURL
		}
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %w", err)
	}
	rawRequest.Data = string(b)
	if !multiPartRequest {
		rawRequest.Data = strings.TrimSuffix(rawRequest.Data, "\r\n")
	}
	return rawRequest, nil
}

func fixUnsafeRequestPath(baseURL *url.URL, requestPath string, request []byte) []byte {
	fixedPath := path.Join(baseURL.Path, requestPath)
	fixed := bytes.Replace(request, []byte(requestPath), []byte(fixedPath), 1)
	return fixed
}

// TryFillCustomHeaders after the Host header
func (r *Request) TryFillCustomHeaders(headers []string) error {
	unsafeBytes := bytes.ToLower(r.UnsafeRawBytes)
	// locate first host header
	hostHeaderIndex := bytes.Index(unsafeBytes, []byte("host:"))
	if hostHeaderIndex > 0 {
		// attempt to locate next newline
		newLineIndex := bytes.Index(unsafeBytes[hostHeaderIndex:], []byte("\r\n"))
		if newLineIndex > 0 {
			newLineIndex += hostHeaderIndex + 2
			// insert custom headers
			var buf bytes.Buffer
			buf.Write(r.UnsafeRawBytes[:newLineIndex])
			for _, header := range headers {
				buf.WriteString(fmt.Sprintf("%s\r\n", header))
			}
			buf.Write(r.UnsafeRawBytes[newLineIndex:])
			r.UnsafeRawBytes = buf.Bytes()
			return nil
		}
		return errors.New("no new line found at the end of host header")
	}

	return errors.New("no host header found")
}
