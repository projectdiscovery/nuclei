package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// The scan response cache must never serve or store a request that follows
// redirects: a chain is several responses, a cache entry is one, and the key
// does not carry the redirect policy.
func TestFollowsRedirects(t *testing.T) {
	mk := func(flow httpclientpool.RedirectFlow, opts *types.Options) *Request {
		return &Request{
			options:           &protocols.ExecutorOptions{Options: opts},
			connConfiguration: &httpclientpool.Configuration{RedirectFlow: flow},
		}
	}
	cases := []struct {
		name string
		req  *Request
		want bool
	}{
		{"template does not follow", mk(httpclientpool.DontFollowRedirect, &types.Options{}), false},
		{"template follows all", mk(httpclientpool.FollowAllRedirect, &types.Options{}), true},
		{"template follows same host", mk(httpclientpool.FollowSameHostRedirect, &types.Options{}), true},
		{"template follows same scheme", mk(httpclientpool.FollowSameSchemeRedirect, &types.Options{}), true},
		{"global -fr overrides template", mk(httpclientpool.DontFollowRedirect, &types.Options{FollowRedirects: true}), true},
		{"global -fhr overrides template", mk(httpclientpool.DontFollowRedirect, &types.Options{FollowHostRedirects: true}), true},
		{"-disable-redirects wins", mk(httpclientpool.FollowAllRedirect, &types.Options{FollowRedirects: true, DisableRedirects: true}), false},
		{"unknown options stay out of cache", &Request{}, true},
	}
	for _, c := range cases {
		if got := c.req.followsRedirects(); got != c.want {
			t.Errorf("%s: followsRedirects()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestUsesResponseCache(t *testing.T) {
	plain := &Request{options: &protocols.ExecutorOptions{Options: &types.Options{}}, connConfiguration: &httpclientpool.Configuration{}}
	if !plain.usesResponseCache(&generatedRequest{original: &Request{}}) {
		t.Fatal("an ordinary request may use the cache")
	}
	optOut := &Request{DisableHTTPCache: true, options: plain.options, connConfiguration: plain.connConfiguration}
	if optOut.usesResponseCache(&generatedRequest{original: optOut}) {
		t.Fatal("disable-http-cache must keep the request out of the cache")
	}
	if plain.usesResponseCache(&generatedRequest{original: &Request{Race: true}}) {
		t.Fatal("race requests must all reach the server")
	}
	redirect := &Request{options: plain.options, connConfiguration: &httpclientpool.Configuration{RedirectFlow: httpclientpool.FollowAllRedirect}}
	if redirect.usesResponseCache(&generatedRequest{original: redirect}) {
		t.Fatal("redirect-following requests must stay out of the cache")
	}
}
