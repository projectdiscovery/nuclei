package http

import (
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
)

// followsRedirects reports whether this request's client follows redirects,
// resolving the policy the same way httpclientpool does: the template setting,
// overridden by the global follow flags, cancelled by -disable-redirects.
//
// The scan response cache must stay out of such requests. A redirect chain is
// several responses, and a cache entry is one: serving it would hide the chain
// from matchers that walk it. The cache key also does not carry the redirect
// policy, so a followed and an unfollowed request for the same URL would
// otherwise share one entry and each see the other's response.
func (request *Request) followsRedirects() bool {
	if request.options == nil || request.options.Options == nil {
		return true // unknown policy: stay out of the cache
	}
	opts := request.options.Options
	if opts.DisableRedirects {
		return false
	}
	if opts.ShouldFollowHTTPRedirects() {
		return true
	}
	return request.connConfiguration == nil ||
		request.connConfiguration.RedirectFlow != httpclientpool.DontFollowRedirect
}

// usesResponseCache reports whether this request may be served from, or stored
// in, the scan response cache. A template's own disable-http-cache opts out,
// race requests must all reach the server, and redirect-following requests
// carry a chain the cache cannot represent.
func (request *Request) usesResponseCache(req *generatedRequest) bool {
	if request.DisableHTTPCache || request.followsRedirects() {
		return false
	}
	return req == nil || req.original == nil || !req.original.Race
}

// respCacheKey is the response cache key for a request. Inputs that share a
// URL but dial different addresses (-scan-all-ips, -iv) must not share
// responses, so the selected IP is part of the key.
func respCacheKey(input *contextargs.Context, req *http.Request) string {
	key := httprespcache.KeyFromRequest(req)
	if key == "" || input == nil || input.MetaInput == nil || input.MetaInput.CustomIP == "" {
		return key
	}
	return key + " |ip:" + input.MetaInput.CustomIP
}

// isHTTPToHTTPSMismatch reports the 400 a server returns for plain HTTP sent to
// an HTTPS port. The scan records a correction for that host:port, so this
// response must not be cached: a later hit would skip the correction.
func isHTTPToHTTPSMismatch(statusCode int, body string) bool {
	return statusCode == http.StatusBadRequest && strings.Contains(body, httpToHTTPSMismatchSignature)
}
