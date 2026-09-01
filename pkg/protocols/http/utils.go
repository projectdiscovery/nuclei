package http

import (
	"bytes"
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/utils/errkit"
)

// dump creates a dump of the http request in form of a byte slice
func dump(req *generatedRequest, reqURL string) ([]byte, error) {
	if req.request != nil {
		// Clone the wrapper first: Request.Clone updates its receiver, which can
		// otherwise change the URL used by request post-processors/signers.
		requestCopy := *req.request
		requestCopy.Request = req.request.Request.Clone(req.request.Context())
		requestCopy.URL = req.request.URL.Clone()
		requestCopy.Request.URL = requestCopy.URL.URL
		if req.request.GetBody != nil {
			body, err := req.request.GetBody()
			if err != nil {
				return nil, errkit.Wrapf(err, "could not clone request body: %v", req.request.String())
			}
			requestCopy.Body = body
		}

		bin, err := requestCopy.Dump()
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

func getHTTPProjectCacheScope(requestDump []byte, scheme, host string) []byte {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.ToLower(strings.TrimSpace(host))
	if scheme == "" || host == "" {
		return requestDump
	}

	var scoped bytes.Buffer
	scoped.Grow(len(scheme) + len(host) + len(requestDump) + 4)
	_, _ = scoped.WriteString(scheme)
	_, _ = scoped.WriteString("://")
	_, _ = scoped.WriteString(host)
	_, _ = scoped.WriteString("\n")
	_, _ = scoped.Write(requestDump)
	return scoped.Bytes()
}
