package requests

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/pkg/matchers"
)

// Request contains a request to be made from a template
type Request struct {
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
	Matchers []*matchers.Matcher `yaml:"matchers"`
}

// MakeRequest creates a *http.Request from a request template
func (r *Request) MakeRequest(baseURL string) ([]*http.Request, error) {
	var requests []*http.Request

	for _, path := range r.Path {
		// Replace the BaseURL portion with the actual base URL of the host
		url := strings.Replace(path, "{{BaseURL}}", baseURL, -1)

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
		requests = append(requests, req)
	}

	return requests, nil
}
