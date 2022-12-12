package raw

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/projectdiscovery/rawhttp/client"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	// parse Input URL
	inputURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %w", err)
	}
	inputParams := inputURL.Query()

	// Joins input url and new url preserving query parameters
	joinPath := func(relpath string) (string, error) {
		newpath := ""
		// Join path with input along with parameters
		relUrl, relerr := url.Parse(relpath)
		if relUrl == nil {
			newpath = path.Join(inputURL.Path, relpath)
		} else {
			newpath = path.Join(inputURL.Path, relUrl.Path)
			if len(relUrl.Query()) > 0 {
				relParam := relUrl.Query()
				for k := range relParam {
					inputParams.Add(k, relParam.Get(k))
				}
			}
		}
		if len(inputParams) > 0 {
			newpath += "?" + inputParams.Encode()
		}
		return newpath, relerr
	}

	rawrequest, err := readRawRequest(request, unsafe)
	if err != nil {
		return nil, err
	}

	switch {
	// If path is empty do not tamper input url (see doc)
	// can be omitted but makes things clear
	case rawrequest.Path == "":
		rawrequest.Path, _ = joinPath("")

	// full url provided instead of rel path
	case strings.HasPrefix(rawrequest.Path, "http") && !unsafe:
		var parseErr error
		rawrequest.Path, parseErr = joinPath(rawrequest.Path)
		if parseErr != nil {
			return nil, fmt.Errorf("could not parse url:%w", parseErr)
		}
	// If unsafe changes must be made in raw request string iteself
	case unsafe:
		prevPath := rawrequest.Path
		unsafeRelativePath, _ := joinPath(rawrequest.Path)
		// replace itself
		rawrequest.UnsafeRawBytes = bytes.Replace(rawrequest.UnsafeRawBytes, []byte(prevPath), []byte(unsafeRelativePath), 1)

	default:
		rawrequest.Path, _ = joinPath(rawrequest.Path)

	}

	if !unsafe {
		if _, ok := rawrequest.Headers["Host"]; !ok {
			rawrequest.Headers["Host"] = inputURL.Host
		}
		rawrequest.FullURL = fmt.Sprintf("%s://%s%s", inputURL.Scheme, strings.TrimSpace(inputURL.Host), rawrequest.Path)
	}

	return rawrequest, nil

}

// reads raw request line by line following convention
func readRawRequest(request string, unsafe bool) (*Request, error) {
	rawRequest := &Request{
		Headers: make(map[string]string),
	}

	// store body if it is unsafe request
	if unsafe {
		rawRequest.UnsafeRawBytes = []byte(request)
	}

	// parse raw request
	reader := bufio.NewReader(strings.NewReader(request))
read_line:
	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %w", err)
	}
	// ignore all annotations
	if stringsutil.HasPrefixAny(s, "@") {
		goto read_line
	}

	parts := strings.Split(s, " ")
	if len(parts) > 0 {
		rawRequest.Method = parts[0]
		if len(parts) == 2 && strings.Contains(parts[1], "HTTP") {
			// When relative path is missing/ not specified it is considered that
			// request is meant to be untampered at path
			// Ex: GET HTTP/1.1
			parts = []string{parts[0], "", parts[1]}
		}
		if len(parts) < 3 && !unsafe {
			// missing a field
			return nil, fmt.Errorf("malformed request specified: %v", s)
		}

		// relative path
		rawRequest.Path = parts[1]
		// Note: raw request does not URL Encode if needed `+` should be used
		// this can be also be implemented
	}

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

	// Set the request body
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %w", err)
	}
	rawRequest.Data = string(b)
	if !multiPartRequest {
		rawRequest.Data = strings.TrimSuffix(rawRequest.Data, "\r\n")
	}
	return rawRequest, nil

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
