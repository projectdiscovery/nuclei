package raw

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Parse parses a raw request and returns the normalized request.
func Parse(data string, baseURL string) (*fuzzing.NormalizedRequest, error) {
	request, err := raw.Parse(data, baseURL, false)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse raw request")
	}
	req, err := http.NewRequest(request.Method, request.FullURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}
	_, contentOK := request.Headers["Content-Length"]
	if request.Data != "" {
		if contentOK {
			req.ContentLength = int64(len(request.Data))
		}
		req.Body = ioutil.NopCloser(strings.NewReader(request.Data))
	}

	retryable, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not create retryable request")
	}

	normalized, err := fuzzing.NormalizeRequest(retryable)
	if err != nil {
		return nil, errors.Wrap(err, "could not create normalized request")
	}
	return normalized, nil
}
