package http

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/utils/errkit"
)

// dump creates a dump of the http request in form of a byte slice
func dump(req *generatedRequest, reqURL string) ([]byte, error) {
	if req.request != nil {
		// Use a clone to avoid a race condition with the http transport
		bin, err := req.request.Clone(req.request.Context()).Dump()
		if err != nil {
			return nil, errkit.Wrapf(err, "could not dump request: %v", req.request.String())
		}
		return bin, nil
	}
	rawHttpOptions := &rawhttp.Options{CustomHeaders: req.rawRequest.UnsafeHeaders, CustomRawBytes: req.rawRequest.UnsafeRawBytes}
	bin, err := rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), io.NopCloser(strings.NewReader(req.rawRequest.Data)), rawHttpOptions)
	if err != nil {
		return nil, errkit.Wrapf(err, "could not dump request: %v", reqURL)
	}
	return bin, nil
}
