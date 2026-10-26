package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
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

// A body read up to a template's max-size may be cut short. The cache must not
// keep it, or a later template with a larger limit matches against a cut body.
func TestResponseCacheSkipsTruncatedBody(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(strings.Repeat("A", 150) + "TAIL"))
	}))
	defer ts.Close()

	// Other tests change the shared default options, so work on a copy.
	opts := testutils.DefaultOptions.Copy()
	// -response-cache pins one user agent, so identical requests share a key.
	opts.ResponseCache = true
	opts.FollowRedirects = false
	opts.FollowHostRedirects = false
	opts.ResponseReadSize = 0
	// A custom header makes a request uncacheable.
	opts.CustomHeaders = nil
	testutils.Init(opts)
	cache := httprespcache.New()

	execute := func(id string, maxSize int) string {
		request := &Request{ID: id, MaxSize: maxSize, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Path: []string{"{{BaseURL}}/big"}}
		executerOptions := testutils.NewMockExecuterOptions(opts, &testutils.TemplateInfo{
			ID:   id,
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})
		executerOptions.HTTPResponseCache = cache
		require.NoError(t, request.Compile(executerOptions))

		var body string
		err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ts.URL), make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
			if event != nil && event.InternalEvent != nil {
				body, _ = event.InternalEvent["body"].(string)
			}
		})
		require.NoError(t, err)
		return body
	}

	require.Len(t, execute("small", 50), 50)
	require.Equal(t, 0, cache.Len(), "truncated body must not be cached")

	require.True(t, strings.HasSuffix(execute("full", 0), "TAIL"))
	require.Equal(t, int32(2), hits.Load())
	require.Equal(t, 1, cache.Len())

	require.Len(t, execute("small-again", 50), 50, "a cached full body is still cut to the reader's limit")
	require.Equal(t, int32(2), hits.Load())
}
