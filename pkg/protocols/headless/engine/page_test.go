package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

var errCDPCallBlocked = errors.New("cdp call remained blocked")

type blockingCDPClient struct {
	method string
	wait   time.Duration
	events chan *cdp.Event
}

type countingCDPClient struct {
	events chan *cdp.Event
	calls  atomic.Int32
}

func (c *countingCDPClient) Event() <-chan *cdp.Event {
	return c.events
}

func (c *countingCDPClient) Call(context.Context, string, string, interface{}) ([]byte, error) {
	c.calls.Add(1)
	return []byte("{}"), nil
}

func newBlockingCDPClient(method string, wait time.Duration) *blockingCDPClient {
	return &blockingCDPClient{method: method, wait: wait, events: make(chan *cdp.Event)}
}

func (c *blockingCDPClient) Event() <-chan *cdp.Event {
	return c.events
}

func (c *blockingCDPClient) Call(ctx context.Context, _ string, method string, _ interface{}) ([]byte, error) {
	if method != c.method {
		return []byte("{}"), nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(c.wait):
		return nil, errCDPCallBlocked
	}
}

func TestRunCancelsBlockedPageCreation(t *testing.T) {
	client := newBlockingCDPClient("Target.createTarget", 500*time.Millisecond)
	instance := &Instance{
		browser: &Browser{},
		engine:  rod.New().Client(client),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, _, err := instance.Run(
		contextargs.NewWithInput(ctx, "http://example.com"),
		nil,
		nil,
		&Options{Timeout: time.Second},
	)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 200*time.Millisecond)
}

func TestPageCloseUsesDirectTargetCloseAfterRequestCancellation(t *testing.T) {
	client := &countingCDPClient{events: make(chan *cdp.Event)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rodPage := rod.New().Client(client).Context(ctx).PageFromSession(proto.TargetSessionID("session-id"))
	page := &Page{page: rodPage}

	page.Close()

	require.Equal(t, int32(1), client.calls.Load())
}

// A 429 with an empty body makes the browser fail the navigation, so the
// status has to reach the caller on the error path too.
func TestRunReportsNavigationResponseWhenActionsFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	opts := &types.Options{}
	_ = protocolstate.Init(opts)
	instance, err := sharedBrowser.NewInstance()
	require.NoError(t, err)
	defer func() { _ = instance.Close() }()

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	input.CookieJar, err = cookiejar.New(nil)
	require.NoError(t, err)

	var got *http.Response
	actions := []*Action{{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}}, {ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}}}
	_, _, err = instance.Run(input, actions, nil, &Options{Timeout: 20 * time.Second, Options: opts, OnNavigationResponse: func(resp *http.Response) { got = resp }})
	require.Error(t, err, "the browser fails a navigation to an empty error page")
	require.NotNil(t, got)
	require.Equal(t, http.StatusTooManyRequests, got.StatusCode)
	require.Equal(t, "7", got.Header.Get("Retry-After"))
}

func TestNavigationResponseIsNilWithoutHistory(t *testing.T) {
	page := &Page{mutex: &sync.RWMutex{}}
	require.Nil(t, page.NavigationResponse())
	require.Nil(t, page.FirstResponse())
}

func TestNavigationResponseFollowsRedirects(t *testing.T) {
	tests := []struct {
		name    string
		history []HistoryData
		status  int
	}{
		{
			name: "native absolute request line",
			history: []HistoryData{
				{RawRequest: "GET https://example.com/ HTTP/1.1\n", RawResponse: "HTTP/1.1 302 Found\nLocation: /login?next=1\n\n"},
				{RawRequest: "GET https://example.com/style.css HTTP/1.1\n", RawResponse: "HTTP/1.1 200 OK\n\n"},
				{RawRequest: "GET https://example.com/login?next=1 HTTP/1.1\n", RawResponse: "HTTP/1.1 429 Too Many Requests\nRetry-After: 7\n\n"},
			},
			status: http.StatusTooManyRequests,
		},
		{
			name: "router path and host header across schemes",
			history: []HistoryData{
				{RawRequest: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", RawResponse: "HTTP/1.1 301 Moved Permanently\nLocation: https://example.com/home\n\n"},
				{RawRequest: "GET /home HTTP/1.1\r\nHost: example.com\r\n\r\n", RawResponse: "HTTP/1.1 503 Service Unavailable\n\n"},
			},
			status: http.StatusServiceUnavailable,
		},
		{
			name: "redirect target never recorded",
			history: []HistoryData{
				{RawRequest: "GET https://example.com/ HTTP/1.1\n", RawResponse: "HTTP/1.1 302 Found\nLocation: https://other.example/\n\n"},
				{RawRequest: "GET https://example.com/app.js HTTP/1.1\n", RawResponse: "HTTP/1.1 429 Too Many Requests\n\n"},
			},
			status: http.StatusFound,
		},
		{
			name: "no redirect keeps the first response",
			history: []HistoryData{
				{RawRequest: "GET https://example.com/ HTTP/1.1\n", RawResponse: "HTTP/1.1 200 OK\n\n"},
				{RawRequest: "GET https://example.com/api HTTP/1.1\n", RawResponse: "HTTP/1.1 429 Too Many Requests\n\n"},
			},
			status: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := &Page{mutex: &sync.RWMutex{}, History: tt.history}
			resp := page.NavigationResponse()
			require.NotNil(t, resp)
			require.Equal(t, tt.status, resp.StatusCode)
			require.Equal(t, parseHistoryResponse(tt.history[0].RawResponse).StatusCode, page.FirstResponse().StatusCode)
		})
	}
}
