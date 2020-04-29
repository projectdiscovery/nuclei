package requests

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/pkg/extractors"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/valyala/fasttemplate"
)

// HTTPRequest contains a request to be made from a template
type HTTPRequest struct {
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `yaml:"method"`
	// Path contains the path/s for the request
	Path []string `yaml:"path"`
	// Headers contains headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `yaml:"body,omitempty"`
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
	// matchersCondition is internal condition for the matchers.
	matchersCondition matchers.ConditionType
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `yaml:"max-redirects,omitempty"`
	// Raw contains raw requests
	Raw []string `yaml:"raw,omitempty"`
}

// GetMatchersCondition returns the condition for the matcher
func (r *HTTPRequest) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// SetMatchersCondition sets the condition for the matcher
func (r *HTTPRequest) SetMatchersCondition(condition matchers.ConditionType) {
	r.matchersCondition = condition
}

// MakeHTTPRequest creates a *http.Request from a request configuration
func (r *HTTPRequest) MakeHTTPRequest(baseURL string) ([]*retryablehttp.Request, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	hostname := parsed.Hostname()

	values := map[string]interface{}{
		"BaseURL":  baseURL,
		"Hostname": hostname,
	}

	if len(r.Raw) > 0 {
		return r.makeHTTPRequestFromRaw(baseURL, values)
	}

	return r.makeHTTPRequestFromModel(baseURL, values)
}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *HTTPRequest) makeHTTPRequestFromModel(baseURL string, values map[string]interface{}) (requests []*retryablehttp.Request, err error) {
	for _, path := range r.Path {
		// Replace the dynamic variables in the URL if any
		t := fasttemplate.New(path, "{{", "}}")
		url := t.ExecuteString(values)

		// Build a request on the specified URL
		req, err := http.NewRequest(r.Method, url, nil)
		if err != nil {
			return nil, err
		}

		request, err := r.fillRequest(req, values)
		if err != nil {
			return nil, err
		}

		requests = append(requests, request)
	}

	return
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *HTTPRequest) makeHTTPRequestFromRaw(baseURL string, values map[string]interface{}) (requests []*retryablehttp.Request, err error) {
	for _, raw := range r.Raw {
		// Add trailing line
		raw += "\n"

		// Replace the dynamic variables in the URL if any
		t := fasttemplate.New(raw, "{{", "}}")
		raw := t.ExecuteString(values)

		// Build a parsed request from raw
		parsedReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return nil, err
		}

		// requests generated from http.ReadRequest have incorrect RequestURI, so they
		// cannot be used to perform another request directly, we need to generate a new one
		// with the new target url
		finalURL := fmt.Sprintf("%s%s", baseURL, parsedReq.URL)
		req, err := http.NewRequest(r.Method, finalURL, parsedReq.Body)
		if err != nil {
			return nil, err
		}

		// copy headers
		req.Header = parsedReq.Header.Clone()

		request, err := r.fillRequest(req, values)
		if err != nil {
			return nil, err
		}

		requests = append(requests, request)
	}

	return requests, nil
}

func (r *HTTPRequest) fillRequest(req *http.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	// Check if the user requested a request body
	if r.Body != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(r.Body))
	}

	// Set the header values requested
	for header, value := range r.Headers {
		t := fasttemplate.New(value, "{{", "}}")
		val := t.ExecuteString(values)
		req.Header.Set(header, val)
	}

	// Set some headers only if the header wasn't supplied by the user
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Nuclei (@pdiscoveryio)")
	}

	if _, ok := req.Header["Accept"]; !ok {
		req.Header.Set("Accept", "*/*")
	}
	if _, ok := req.Header["Accept-Language"]; !ok {
		req.Header.Set("Accept-Language", "en")
	}
	req.Header.Set("Connection", "close")
	req.Close = true

	return retryablehttp.FromRequest(req)
}
