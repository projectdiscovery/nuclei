// Package raw parses input files holding raw HTTP requests, the shape produced
// by "copy as raw request" in Burp and browser devtools and stored in .http
// files. It is the shortest path from a single request to a DAST scan, for
// targets that have no OpenAPI spec or captured traffic to feed in.
package raw

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

// requestSeparator delimits requests when a file carries more than one,
// following the .http file convention
const requestSeparator = "###"

// RawFormat is a parser for files containing one or more raw HTTP requests
type RawFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new raw HTTP request parser
func New() *RawFormat {
	return &RawFormat{}
}

var _ formats.Format = &RawFormat{}

// Name returns the name of the format
func (r *RawFormat) Name() string {
	return "http"
}

func (r *RawFormat) SetOptions(options formats.InputFormatOptions) {
	r.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (r *RawFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return errors.Wrap(err, "could not read raw request file")
	}
	for _, request := range splitRequests(string(data)) {
		reqResp, err := types.ParseRawRequest(terminateHeaders(request))
		if err != nil {
			gologger.Warning().Msgf("http: could not parse raw request in %s: %s\n", filePath, err)
			continue
		}
		if reqResp.URL.Host == "" {
			gologger.Warning().Msgf("http: skipped raw request in %s: no target, add a Host header or an absolute request target\n", filePath)
			continue
		}
		if reqResp.URL.Scheme == "" {
			// nothing in the request states the scheme, so settle it the same
			// way nuclei settles it for scheme-less list inputs
			reqResp.URL.Scheme = utils.DetermineSchemeOrder(reqResp.URL.Host)[0]
		}
		resultsCb(reqResp)
	}
	return nil
}

// splitRequests splits the file contents into individual raw requests
func splitRequests(data string) []string {
	var requests []string
	var current []string
	flush := func() {
		if request := strings.Join(current, "\n"); strings.TrimSpace(request) != "" {
			requests = append(requests, strings.TrimLeft(request, "\r\n"))
		}
		current = nil
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), requestSeparator) {
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()
	return requests
}

// terminateHeaders appends the blank line that separates headers from the body.
// Requests copied out of a browser or Burp routinely end at the last header,
// and the parser needs that terminator to know where the headers stop.
func terminateHeaders(request string) string {
	if strings.Contains(request, "\n\r\n") || strings.Contains(request, "\n\n") {
		return request
	}
	return request + "\r\n\r\n"
}
