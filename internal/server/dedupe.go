package server

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/input/dedupe"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
)

// requestDeduplicator wraps the shared HTTP request deduplicator used by
// live DAST and multiformat fuzz inputs.
type requestDeduplicator struct {
	inner *dedupe.RequestDeduplicator
}

func newRequestDeduplicator() *requestDeduplicator {
	return &requestDeduplicator{inner: dedupe.NewRequestDeduplicator()}
}

func (r *requestDeduplicator) isDuplicate(req *types.RequestResponse) bool {
	return r.inner.IsDuplicate(req)
}
