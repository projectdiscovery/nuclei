package http

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/rawhttp"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// dump creates a dump of the http request in form of a byte slice
func dump(req *generatedRequest, reqURL string) ([]byte, error) {
	if req.request != nil {
		bin, err := req.request.Dump()
		if err != nil {
			return nil, errorutil.NewWithErr(err).WithTag("http").Msgf("could not dump request: %v", req.request.URL.String())
		}
		return bin, nil
	}
	rawHttpOptions := &rawhttp.Options{CustomHeaders: req.rawRequest.UnsafeHeaders, CustomRawBytes: req.rawRequest.UnsafeRawBytes}
	bin, err := rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), io.NopCloser(strings.NewReader(req.rawRequest.Data)), rawHttpOptions)
	if err != nil {
		return nil, errorutil.NewWithErr(err).WithTag("http").Msgf("could not dump request: %v", reqURL)
	}
	return bin, nil
}
