package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestRespCacheKeyIncludesCustomIP(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	plain := contextargs.NewWithInput(context.Background(), "http://example.com/")
	a := contextargs.NewWithInput(context.Background(), "http://example.com/")
	a.MetaInput.CustomIP = "10.0.0.1"
	b := contextargs.NewWithInput(context.Background(), "http://example.com/")
	b.MetaInput.CustomIP = "10.0.0.2"
	if respCacheKey(a, req) == respCacheKey(b, req) {
		t.Fatal("inputs that dial different IPs must not share a cache key")
	}
	if respCacheKey(plain, req) == respCacheKey(a, req) {
		t.Fatal("an IP-pinned input must not share the plain input's key")
	}
}

func TestIsHTTPToHTTPSMismatch(t *testing.T) {
	if !isHTTPToHTTPSMismatch(400, "<h1>The plain HTTP request was sent to HTTPS port</h1>") {
		t.Fatal("expected the mismatch to be recognised")
	}
	if isHTTPToHTTPSMismatch(400, "bad request") || isHTTPToHTTPSMismatch(200, "The plain HTTP request was sent to HTTPS port") {
		t.Fatal("only the 400 with the mismatch message counts")
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

// Identical cacheable requests from different templates that run at the same
// time send one request on the wire. Without the cache each one is sent.
func TestResponseCacheSharesInFlight(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("shared"))
	}))
	defer ts.Close()

	opts := testutils.DefaultOptions.Copy()
	opts.ResponseCache = true
	opts.FollowRedirects = false
	opts.FollowHostRedirects = false
	opts.CustomHeaders = nil
	testutils.Init(opts)

	run := func(cache *httprespcache.Cache) []string {
		hits.Store(0)
		const n = 4
		bodies := make([]string, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			id := "tpl-" + strconv.Itoa(i)
			request := &Request{ID: id, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Path: []string{"{{BaseURL}}/slow"}}
			executerOptions := testutils.NewMockExecuterOptions(opts, &testutils.TemplateInfo{
				ID:   id,
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
			})
			executerOptions.HTTPResponseCache = cache
			require.NoError(t, request.Compile(executerOptions))
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ts.URL), make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
					if event != nil && event.InternalEvent != nil {
						bodies[i], _ = event.InternalEvent["body"].(string)
					}
				})
				require.NoError(t, err)
			}(i)
		}
		wg.Wait()
		return bodies
	}

	for _, body := range run(httprespcache.New()) {
		require.Equal(t, "shared", body)
	}
	require.Equal(t, int32(1), hits.Load(), "concurrent identical requests must share one request")

	for _, body := range run(nil) {
		require.Equal(t, "shared", body)
	}
	require.Equal(t, int32(4), hits.Load(), "without the cache every request is sent")
}
