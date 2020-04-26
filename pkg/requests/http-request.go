package requests

import (
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
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `yaml:"redirects,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `yaml:"max-redirects,omitempty"`
}

// MakeHTTPRequest creates a *http.Request from a request template
func (r *HTTPRequest) MakeHTTPRequest(baseURL string) ([]*retryablehttp.Request, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	hostname := parsed.Hostname()

	requests := make([]*retryablehttp.Request, 0, len(r.Path))
	for _, path := range r.Path {
		// Replace the dynamic variables in the URL if any
		t := fasttemplate.New(path, "{{", "}}")
		url := t.ExecuteString(map[string]interface{}{
			"BaseURL":  baseURL,
			"Hostname": hostname,
		})

		// Build a request on the specified URL
		req, err := http.NewRequest(r.Method, url, nil)
		if err != nil {
			return nil, err
		}

		// Check if the user requested a request body
		if r.Body != "" {
			req.Body = ioutil.NopCloser(strings.NewReader(r.Body))
		}

		// Set the header values requested
		for header, value := range r.Headers {
			req.Header.Set(header, value)
		}

		// Set some headers only if the header wasn't supplied by the user
		if _, ok := r.Headers["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "Nuclei (@pdiscoveryio)")
		}
		if _, ok := r.Headers["Accept"]; !ok {
			req.Header.Set("Accept", "*/*")
		}
		if _, ok := r.Headers["Accept-Language"]; !ok {
			req.Header.Set("Accept-Language", "en")
		}
		req.Header.Set("Connection", "close")
		req.Close = true

		request, err := retryablehttp.FromRequest(req)
		if err != nil {
			return nil, err
		}

		requests = append(requests, request)
	}

	return requests, nil
}
