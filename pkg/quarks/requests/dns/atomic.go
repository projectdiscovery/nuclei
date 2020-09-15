package dns

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
)

// CompiledRequest is the compiled dns request structure created
// by parsing and processing the data from read file.
type CompiledRequest struct {
	AtomicRequests []AtomicRequest
}

// AtomicRequest is a single atomic dns request sent to a server
type AtomicRequest struct {
	retries   int
	recursive bool
	reqType   uint16
	class     uint16
	fqdn      string

	matchers   []matchers.CompiledMatcher
	extractors []extractors.CompiledExtractor
}

// Compare checks if an atomic request is exactly same as the other request.
func (a *AtomicRequest) Compare(req *AtomicRequest) bool {
	if a.class != req.class {
		return false
	}
	if a.reqType != req.reqType {
		return false
	}
	if a.retries != req.retries || a.recursive != req.recursive {
		return false
	}
	if !strings.EqualFold(a.fqdn, req.fqdn) {
		return false
	}
	return true
}
