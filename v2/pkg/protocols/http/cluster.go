package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/compare"
)

// CanCluster returns true if the request can be clustered.
//
// This used by the clustering engine to decide whether two requests
// are similar enough to be considered one and can be checked by
// just adding the matcher/extractors for the request and the correct IDs.
func (request *Request) CanCluster(other *Request) bool {
	if len(request.Payloads) > 0 || len(request.Raw) > 0 || len(request.Body) > 0 || request.Unsafe || request.ReqCondition || request.Name != "" {
		return false
	}
	if request.Method != other.Method ||
		request.MaxRedirects != other.MaxRedirects ||
		request.CookieReuse != other.CookieReuse ||
		request.Redirects != other.Redirects {
		return false
	}
	if !compare.StringSlice(request.Path, other.Path) {
		return false
	}
	if !compare.StringMap(request.Headers, other.Headers) {
		return false
	}
	return true
}
