package httpclientpool

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	"github.com/stretchr/testify/require"
)

func newSharingTransport(base http.RoundTripper) *sharingTransport {
	return &sharingTransport{base: base, shared: &sharedResponses{entries: make(map[string]*sharedEntry), order: list.New(), maxBytes: sharedResponsesMaxBytes}}
}

func sharedGet(t *testing.T, transport http.RoundTripper, method, url, templateID string, header http.Header) string {
	t.Helper()
	ctx := context.Background()
	if templateID != "" {
		ctx = WithSharedResponse(ctx, templateID)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestSharedResponsesSendEachRequestOncePerScan(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		_, _ = io.WriteString(w, r.URL.Path+strings.Repeat("!", int(n)))
	}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)

	first := sharedGet(t, transport, http.MethodGet, server.URL+"/a", "one", nil)
	require.Equal(t, first, sharedGet(t, transport, http.MethodGet, server.URL+"/a", "two", nil), "another template gets the stored response")
	require.EqualValues(t, 1, hits.Load())

	// nuclei builds a GET with an empty body
	empty, err := retryablehttp.NewRequestWithContext(WithSharedResponse(context.Background(), "four"), http.MethodGet, server.URL+"/a", strings.NewReader(""))
	require.NoError(t, err)
	resp, err := transport.RoundTrip(empty.Request)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.EqualValues(t, 1, hits.Load(), "an empty body is no body")

	sharedGet(t, transport, http.MethodGet, server.URL+"/a", "one", nil)
	require.EqualValues(t, 2, hits.Load(), "a template repeating its own request sends it")

	sharedGet(t, transport, http.MethodGet, server.URL+"/a", "", nil)
	require.EqualValues(t, 3, hits.Load(), "an unmarked request is always sent")

	sharedGet(t, transport, http.MethodGet, server.URL+"/a", "three", http.Header{"Cookie": {"session=1"}})
	require.EqualValues(t, 4, hits.Load(), "other cookies make another request")

	picked := func(i int) http.Header { return http.Header{"User-Agent": {useragent.UserAgents[i].Raw}} }
	sharedGet(t, transport, http.MethodGet, server.URL+"/b", "one", picked(0))
	sharedGet(t, transport, http.MethodGet, server.URL+"/b", "two", picked(1))
	require.EqualValues(t, 5, hits.Load(), "a User-Agent nuclei picked at random is not part of the request")
	sharedGet(t, transport, http.MethodGet, server.URL+"/b", "three", http.Header{"User-Agent": {"custom-scanner"}})
	require.EqualValues(t, 6, hits.Load(), "one a template sets is")

	for range 2 {
		// A new request each time. Clone shares the body, so a second clone
		// of one request can send ContentLength with an already-read body.
		req, err := http.NewRequestWithContext(WithSharedResponse(context.Background(), "one"), http.MethodPost, server.URL+"/a", strings.NewReader("x"))
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	require.EqualValues(t, 8, hits.Load(), "a request with a body is always sent")
}

func TestSharedResponsesWaitForTheRequestInFlight(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		_, _ = io.WriteString(w, "slow")
	}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)

	var wg sync.WaitGroup
	bodies := make([]string, 5)
	for i := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bodies[i] = sharedGet(t, transport, http.MethodGet, server.URL, "template-"+string(rune('a'+i)), nil)
		}()
	}
	require.Eventually(t, func() bool { return hits.Load() > 0 }, 5*time.Second, time.Millisecond)
	close(release)
	wg.Wait()
	require.EqualValues(t, 1, hits.Load())
	require.Equal(t, []string{"slow", "slow", "slow", "slow", "slow"}, bodies)
}

func TestSharedResponsesSendLargeBodiesEachTime(t *testing.T) {
	var hits atomic.Int32
	large := strings.Repeat("x", sharedResponseMaxBody+10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, large)
	}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)

	require.Equal(t, large, sharedGet(t, transport, http.MethodGet, server.URL, "one", nil), "the whole body still arrives")
	require.Equal(t, large, sharedGet(t, transport, http.MethodGet, server.URL, "two", nil))
	require.EqualValues(t, 2, hits.Load())
}

type failOnce struct {
	failed atomic.Bool
	base   http.RoundTripper
}

func (f *failOnce) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.failed.CompareAndSwap(false, true) {
		return nil, errors.New("connection reset")
	}
	return f.base.RoundTrip(req)
}

func TestSharedResponsesDoNotKeepFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	transport := newSharingTransport(&failOnce{base: http.DefaultTransport})

	req, err := http.NewRequestWithContext(WithSharedResponse(context.Background(), "one"), http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	_, err = transport.RoundTrip(req)
	require.Error(t, err)
	require.Equal(t, "ok", sharedGet(t, transport, http.MethodGet, server.URL, "two", nil), "the next template sends it again")
}

func TestSharedResponsesStartEmptyEachScan(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	opts := newTestOptions(t, "test-shared-responses-reset")
	transport := &sharingTransport{base: http.DefaultTransport, shared: getSharedResponses(opts)}

	sharedGet(t, transport, http.MethodGet, server.URL, "one", nil)
	sharedGet(t, transport, http.MethodGet, server.URL, "two", nil)
	require.EqualValues(t, 1, hits.Load())

	// an SDK engine runs its next scan on the same execution
	ResetSharedResponses(opts)
	sharedGet(t, transport, http.MethodGet, server.URL, "two", nil)
	require.EqualValues(t, 2, hits.Load(), "a new scan does not see the responses of the last one")
}

func TestSharedResponsesCapCountsBodylessResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)
	transport.shared.maxBytes = 20 * sharedEntryOverhead

	for i := range 40 {
		sharedGet(t, transport, http.MethodHead, fmt.Sprintf("%s/%d", server.URL, i), "one", nil)
	}
	require.LessOrEqual(t, transport.shared.bytes, transport.shared.maxBytes)
	require.Less(t, len(transport.shared.entries), 20, "HEAD responses are evicted too")
}

func TestSharedResponsesKeepHeadContentLength(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)

	length := func(templateID string) int64 {
		t.Helper()
		req, err := http.NewRequestWithContext(WithSharedResponse(context.Background(), templateID), http.MethodHead, server.URL, nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp.ContentLength
	}

	require.Equal(t, int64(1234), length("one"))
	require.Equal(t, int64(1234), length("two"), "a reused HEAD keeps the length the server advertised")
	require.EqualValues(t, 1, hits.Load())
}

func TestSharedResponsesDoNotKeepRefusals(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Error(w, "no", status)
			}))
			defer server.Close()
			transport := newSharingTransport(http.DefaultTransport)

			sharedGet(t, transport, http.MethodGet, server.URL, "one", nil)
			sharedGet(t, transport, http.MethodGet, server.URL, "two", nil)
			require.EqualValues(t, 2, hits.Load())
		})
	}
}

func TestSharedResponsesKeepNotFound(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	transport := newSharingTransport(http.DefaultTransport)

	sharedGet(t, transport, http.MethodGet, server.URL, "one", nil)
	sharedGet(t, transport, http.MethodGet, server.URL, "two", nil)
	require.EqualValues(t, 1, hits.Load())
}

// shortBody yields a prefix and then ErrUnexpectedEOF, which is what a
// response with a Content-Length longer than its body looks like.
type shortBody struct {
	prefix []byte
	sent   bool
}

func (s *shortBody) Read(p []byte) (int, error) {
	if !s.sent {
		s.sent = true
		n := copy(p, s.prefix)
		return n, io.ErrUnexpectedEOF
	}
	return 0, io.ErrUnexpectedEOF
}

func (s *shortBody) Close() error { return nil }

type countingTransport struct {
	hits atomic.Int32
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.hits.Add(1)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Length": {"50000"}},
		ContentLength: 50000,
		Body:          &shortBody{prefix: []byte("fourteen bytes")},
		Request:       req,
	}, nil
}

func TestSharedResponsesDoNotKeepShortReads(t *testing.T) {
	base := &countingTransport{}
	transport := newSharingTransport(base)

	send := func(templateID string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(WithSharedResponse(context.Background(), templateID), http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		return resp
	}

	first := send("one")
	body, err := io.ReadAll(first.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "fourteen bytes", string(body))
	require.Equal(t, int64(50000), first.ContentLength)
	_ = first.Body.Close()

	second := send("two")
	_ = second.Body.Close()
	require.EqualValues(t, 2, base.hits.Load(), "a short read is not reused")
}
