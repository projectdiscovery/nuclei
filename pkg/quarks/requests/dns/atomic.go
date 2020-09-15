package dns

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
)

// CompiledRequest is the compiled dns request structure created
// by parsing and processing the data from read file.
type CompiledRequest struct {
	AtomicRequests []*AtomicRequest
}

// AtomicRequest is a single atomic dns request sent to a server
type AtomicRequest struct {
	Retries   int
	Recursive bool
	ReqType   uint16
	Class     uint16
	FQDN      string

	Matchers   []*matchers.CompiledMatcher
	Extractors []*extractors.CompiledExtractor
}

// Compare checks if an atomic request is exactly same as the other request.
func (a *AtomicRequest) Compare(req *AtomicRequest) bool {
	if a.Class != req.Class {
		return false
	}
	if a.ReqType != req.ReqType {
		return false
	}
	if a.Retries != req.Retries || a.Recursive != req.Recursive {
		return false
	}
	if !strings.EqualFold(a.FQDN, req.FQDN) {
		return false
	}
	return true
}
