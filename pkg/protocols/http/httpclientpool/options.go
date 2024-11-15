package httpclientpool

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/rawhttp"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// WithCustomTimeout is a configuration for custom timeout
type WithCustomTimeout struct {
	Timeout time.Duration
}

// RawHttpRequestOpts is a configuration for raw http request
type RawHttpRequestOpts struct {
	// Method is the http method to use
	Method string
	// URL is the url to request
	URL string
	// Path is request path to use
	Path string
	// Headers is the headers to use
	Headers map[string][]string
	// Body is the body to use
	Body io.Reader
	// Options is more client related options
	Options *rawhttp.Options
}

// SendRawRequest sends a raw http request with the provided options and returns http response
func SendRawRequest(client *rawhttp.Client, opts *RawHttpRequestOpts) (*http.Response, error) {
	resp, err := client.DoRawWithOptions(opts.Method, opts.URL, opts.Path, opts.Headers, opts.Body, opts.Options)
	if err != nil {
		cause := err.Error()
		if stringsutil.ContainsAll(cause, "ReadStatusLine: ", "read: connection reset by peer") {
			// this error is caused when rawhttp client sends a corrupted or malformed request packet to server
			// some servers may attempt gracefully shutdown but most will just abruptly close the connection which results
			// in a connection reset by peer error and this can be safely assumed as 400 Bad Request in terms of normal http flow
			req, reqErr := http.NewRequest(opts.Method, opts.URL, opts.Body)
			if reqErr != nil {
				// failed to build new request mostly because of invalid url or body
				// try again or else return urlErr
				parsed, urlErr := urlutil.ParseAbsoluteURL(opts.URL, true)
				if urlErr != nil {
					return nil, err
				}
				req, reqErr = http.NewRequest(opts.Method, parsed.Host, opts.Body)
				if reqErr != nil {
					return nil, err
				}
				req.URL = parsed.URL
				req.Header = opts.Headers
			}

			// if req is still nil, return error
			if req == nil {
				return nil, err
			}

			req.Header = opts.Headers
			resp = &http.Response{
				Request:    req,
				StatusCode: http.StatusBadRequest,
				Status:     http.StatusText(http.StatusBadRequest),
				Body:       io.NopCloser(strings.NewReader("")),
			}
			return resp, nil
		}
	}
	return resp, err
}
