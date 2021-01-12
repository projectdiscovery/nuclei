package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/compare"
)

// CanCluster returns true if the request can be clustered.
//
// This used by the clustering engine to decide whether two requests
// are similar enough to be considered one and can be checked by
// just adding the matcher/extractors for the request and the correct IDs.
func (r *Request) CanCluster(other *Request) bool {
	if len(r.Payloads) > 0 || len(r.Raw) > 0 || len(r.Body) > 0 || r.Unsafe {
		return false
	}
	if r.Method != other.Method ||
		r.MaxRedirects != other.MaxRedirects ||
		r.CookieReuse != other.CookieReuse ||
		r.Redirects != other.Redirects {
		return false
	}
	if !compare.StringSlice(r.Path, other.Path) {
		return false
	}
	if !compare.StringMap(r.Headers, other.Headers) {
		return false
	}
	return true
}
