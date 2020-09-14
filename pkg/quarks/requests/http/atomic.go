package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
)

// CompiledRequest is the compiled http request structure created
// by parsing and processing the data from read file.
type CompiledRequest struct {
	AtomicRequests []AtomicRequest
}

// AtomicRequest is a single atomic http request sent to a server
type AtomicRequest struct {
	method       string
	redirects    int
	maxRedirects int
	path         string
	headers      map[string]string
	body         string

	matchers   []matchers.CompiledMatcher
	extractors []extractors.CompiledExtractor
}

// Compare checks if an atomic request is exactly same as the other request.
func (a *AtomicRequest) Compare(req *AtomicRequest) bool {

}
