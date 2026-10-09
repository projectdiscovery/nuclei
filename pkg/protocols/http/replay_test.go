package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

type replayedRequest struct {
	method, url, header, body string
}

func TestReplayProxyResendsOnlyMatchedRequests(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hit" {
			_, _ = w.Write([]byte("match-me"))
			return
		}
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer target.Close()

	// a forward proxy receives absolute-form request targets for http URLs
	var mu sync.Mutex
	var replayed []replayedRequest
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		replayed = append(replayed, replayedRequest{method: r.Method, url: r.URL.String(), header: r.Header.Get("X-Marker"), body: string(body)})
		mu.Unlock()
	}))
	defer proxy.Close()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ReplayProxy = proxy.URL
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	templateID := "replay-proxy"
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	request := &Request{
		ID:     templateID,
		Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
		Path:   []string{"{{BaseURL}}/hit", "{{BaseURL}}/miss"},
		Body:   "a=1&b=2",
		Headers: map[string]string{
			"X-Marker": "replayed",
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match-me"},
			}},
		},
	}
	require.NoError(t, request.Compile(executerOpts))

	var findings int
	input := contextargs.NewWithInput(context.Background(), target.URL)
	err := request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult != nil && event.OperatorsResult.Matched {
			findings++
		}
	})
	require.NoError(t, err)
	require.Equal(t, 1, findings)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []replayedRequest{{method: http.MethodPost, url: target.URL + "/hit", header: "replayed", body: "a=1&b=2"}}, replayed)
}

func TestReplayProxyUnsetSendsNothing(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "replay-unset"})

	request := &Request{ID: "replay-unset", Path: []string{"{{BaseURL}}/"}}
	require.NoError(t, request.Compile(executerOpts))
	require.Nil(t, request.replayClient)
}

func TestReplayRequestKeepsBodyWithoutContentLength(t *testing.T) {
	var got replayedRequest
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = replayedRequest{method: r.Method, url: r.URL.String(), body: string(body)}
	}))
	defer proxy.Close()

	options := testutils.DefaultOptions.Copy()
	options.ReplayProxy = proxy.URL
	client, err := newReplayClient(options)
	require.NoError(t, err)
	request := &Request{replayClient: client, options: &protocols.ExecutorOptions{Options: options}}

	// unsafe raw requests are dumped as written, here without Content-Length
	request.replayRequest([]byte("POST /hit HTTP/1.1\r\nHost: target.example\r\n\r\nx=1"), "http://target.example/hit")
	require.Equal(t, replayedRequest{method: http.MethodPost, url: "http://target.example/hit", body: "x=1"}, got)
}

func TestReplayProxySendsRedirectChainOnce(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("match-me"))
			return
		}
		_, _ = w.Write([]byte("match-me"))
	}))
	defer target.Close()

	var mu sync.Mutex
	var replayed []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		replayed = append(replayed, r.URL.String())
		mu.Unlock()
	}))
	defer proxy.Close()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ReplayProxy = proxy.URL
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "replay-redirect",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	request := &Request{
		ID:           "replay-redirect",
		Method:       HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:         []string{"{{BaseURL}}/start"},
		Redirects:    true,
		MaxRedirects: 5,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match-me"},
			}},
		},
	}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), target.URL)
	require.NoError(t, request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {}))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{target.URL + "/start"}, replayed)
}

func TestReplayProxyReplaysRaceRequest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("match-me"))
	}))
	defer target.Close()

	var mu sync.Mutex
	var replayed []replayedRequest
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		replayed = append(replayed, replayedRequest{method: r.Method, url: r.URL.String(), body: string(body)})
		mu.Unlock()
	}))
	defer proxy.Close()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ReplayProxy = proxy.URL
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "replay-race",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	request := &Request{
		ID:                 "replay-race",
		Method:             HTTPMethodTypeHolder{MethodType: HTTPPost},
		Path:               []string{"{{BaseURL}}/race"},
		Body:               "race=1",
		Race:               true,
		RaceNumberRequests: 1,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match-me"},
			}},
		},
	}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), target.URL)
	require.NoError(t, request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(*output.InternalWrappedEvent) {}))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []replayedRequest{{method: http.MethodPost, url: target.URL + "/race", body: "race=1"}}, replayed)
}
