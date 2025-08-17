package raw

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/rawhttp/client"
	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
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
func Parse(request string, inputURL *urlutil.URL, unsafe, disablePathAutomerge bool) (*Request, error) {
	rawrequest, err := readRawRequest(request, unsafe)
	if err != nil {
		return nil, err
	}

	switch {
	// If path is empty do not tamper input url (see doc)
	// can be omitted but makes things clear
	case rawrequest.Path == "":
		if !disablePathAutomerge {
			inputURL.Params.IncludeEquals = true
			rawrequest.Path = inputURL.GetRelativePath()
		}

	// full url provided instead of rel path
	case strings.HasPrefix(rawrequest.Path, "http") && !unsafe:
		urlx, err := urlutil.ParseURL(rawrequest.Path, true)
		if err != nil {
			return nil, errkit.New(fmt.Sprintf("raw: failed to parse url %v from template: %s", rawrequest.Path, err)).Build()
		}
		cloned := inputURL.Clone()
		cloned.Params.IncludeEquals = true
		if disablePathAutomerge {
			cloned.Path = ""
		}
		parseErr := cloned.MergePath(urlx.GetRelativePath(), true)
		if parseErr != nil {
			return nil, errkit.Append(errkit.New(fmt.Sprintf("raw: could not automergepath for template path %v", urlx.GetRelativePath())), parseErr)
		}
		rawrequest.Path = cloned.GetRelativePath()
	// If unsafe changes must be made in raw request string itself
	case unsafe:
		prevPath := rawrequest.Path
		cloned := inputURL.Clone()
		cloned.Params.IncludeEquals = true
		unsafeRelativePath := ""
		if (cloned.Path == "" || cloned.Path == "/") && !strings.HasPrefix(prevPath, "/") {
			// Edgecase if raw unsafe request is
			// GET 1337?with=param HTTP/1.1
			if tmpurl, err := urlutil.ParseRelativePath(prevPath, true); err == nil && !tmpurl.Params.IsEmpty() {
				// if raw request contains parameters
				cloned.Params.Merge(tmpurl.Params.Encode())
				unsafeRelativePath = strings.TrimPrefix(tmpurl.Path, "/") + "?" + cloned.Params.Encode()
			} else {
				// if raw request does not contain param
				if !cloned.Params.IsEmpty() {
					unsafeRelativePath = prevPath + "?" + cloned.Params.Encode()
				} else {
					unsafeRelativePath = prevPath
				}
			}
		} else {
			// Edgecase if raw request is
			// GET / HTTP/1.1
			//use case: https://github.com/projectdiscovery/nuclei/issues/4921
			if rawrequest.Path == "/" && cloned.Path != "" {
				rawrequest.Path = ""
			}

			if disablePathAutomerge {
				cloned.Path = ""
			}
			err = cloned.MergePath(rawrequest.Path, true)
			if err != nil {
				return nil, errkit.New(fmt.Sprintf("raw: failed to automerge %v from unsafe template: %s", rawrequest.Path, err)).Build()
			}
			unsafeRelativePath = cloned.GetRelativePath()
		}
		rawrequest.Path = cloned.GetRelativePath()
		rawrequest.UnsafeRawBytes = bytes.Replace(rawrequest.UnsafeRawBytes, []byte(prevPath), []byte(unsafeRelativePath), 1)

	default:
		cloned := inputURL.Clone()
		cloned.Params.IncludeEquals = true
		// Edgecase if raw request is
		// GET / HTTP/1.1
		//use case: https://github.com/projectdiscovery/nuclei/issues/4921
		if rawrequest.Path == "/" {
			rawrequest.Path = ""
		}

		if disablePathAutomerge {
			cloned.Path = ""
		}
		parseErr := cloned.MergePath(rawrequest.Path, true)
		if parseErr != nil {
			return nil, errkit.Append(errkit.New(fmt.Sprintf("raw: could not automergepath for template path %v", rawrequest.Path)), parseErr)
		}
		rawrequest.Path = cloned.GetRelativePath()
	}

	if !unsafe {
		if _, ok := rawrequest.Headers["Host"]; !ok {
			rawrequest.Headers["Host"] = inputURL.Host
		}
		cloned := inputURL.Clone()
		cloned.Params.IncludeEquals = true
		cloned.Path = ""
		_ = cloned.MergePath(rawrequest.Path, true)
		rawrequest.FullURL = cloned.String()
	}

	return rawrequest, nil
}

// ParseRawRequest parses the raw request as supplied by the user
// this function should only be used for self-contained requests
func ParseRawRequest(request string, unsafe bool) (*Request, error) {
	req, err := readRawRequest(request, unsafe)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(req.Path, "http") {
		urlx, err := urlutil.Parse(req.Path)
		if err != nil {
			return nil, errkit.Append(errkit.New(fmt.Sprintf("failed to parse url %v", req.Path)), err)
		}
		req.Path = urlx.GetRelativePath()
		req.FullURL = urlx.String()
	} else {

		if req.Path == "" {
			return nil, errkit.New("self-contained-raw: path cannot be empty in self contained request").Build()
		}
		// given url is relative construct one using Host Header
		if _, ok := req.Headers["Host"]; !ok {
			return nil, errkit.New("self-contained-raw: host header is required for relative path").Build()
		}
		// Review: Current default scheme in self contained templates if relative path is provided is http
		req.FullURL = fmt.Sprintf("%s://%s%s", urlutil.HTTP, strings.TrimSpace(req.Headers["Host"]), req.Path)
	}
	return req, nil
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

	parts := strings.Fields(s)
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

// ApplyAuthStrategy applies the auth strategy to the request
func (r *Request) ApplyAuthStrategy(strategy authx.AuthStrategy) {
	if strategy == nil {
		return
	}
	switch s := strategy.(type) {
	case *authx.QueryAuthStrategy:
		parsed, err := urlutil.Parse(r.FullURL)
		if err != nil {
			gologger.Error().Msgf("auth strategy failed to parse url: %s got %v", r.FullURL, err)
			return
		}
		for _, p := range s.Data.Params {
			parsed.Params.Add(p.Key, p.Value)
		}
	case *authx.CookiesAuthStrategy:
		var buff bytes.Buffer
		for _, cookie := range s.Data.Cookies {
			buff.WriteString(fmt.Sprintf("%s=%s; ", cookie.Key, cookie.Value))
		}
		if buff.Len() > 0 {
			if val, ok := r.Headers["Cookie"]; ok {
				r.Headers["Cookie"] = strings.TrimSuffix(strings.TrimSpace(val), ";") + "; " + buff.String()
			} else {
				r.Headers["Cookie"] = buff.String()
			}
		}
	case *authx.HeadersAuthStrategy:
		for _, header := range s.Data.Headers {
			r.Headers[header.Key] = header.Value
		}
	case *authx.BearerTokenAuthStrategy:
		r.Headers["Authorization"] = "Bearer " + s.Data.Token
	case *authx.BasicAuthStrategy:
		r.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(s.Data.Username+":"+s.Data.Password))
	default:
		gologger.Warning().Msgf("[raw-request] unknown auth strategy: %T", s)
	}
}
