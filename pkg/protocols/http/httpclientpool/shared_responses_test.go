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

	req, err := http.NewRequestWithContext(WithSharedResponse(context.Background(), "one"), http.MethodPost, server.URL+"/a", strings.NewReader("x"))
	require.NoError(t, err)
	for range 2 {
		resp, err := transport.RoundTrip(req.Clone(req.Context()))
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
