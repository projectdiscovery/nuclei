package http

import (
	"net"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
)

func TestHTTPCompile(t *testing.T) {
	options := testutils.DefaultOptions
	options.CustomHeaders = []string{"User-Agent: test", "Hello: World"}

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		Name: "testing",
		Payloads: map[string]interface{}{
			"username": []string{"admin"},
			"password": []string{"admin", "guest", "password", "test", "12345", "123456"},
		},
		AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
		Raw: []string{`GET /manager/html HTTP/1.1
Host: {{Hostname}}
User-Agent: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)
Connection: close
Authorization: Basic {{username + ':' + password}}
Accept-Encoding: gzip`},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")
	require.Equal(t, 6, request.Requests(), "could not get correct number of requests")
	require.Equal(t, map[string]string{"User-Agent": "test", "Hello": "World"}, request.customHeaders, "could not get correct custom headers")
}

// TestAnalyzeConnectionReuse guards the connection-reuse policy: requests that
// must not reuse pooled keep-alive connections (race, explicit
// "Connection: close", time-based analyzers) must be flagged ReuseUnsafe, while
// everything else stays ReuseSafe so dev's per-host pooling keeps connections alive.
func TestAnalyzeConnectionReuse(t *testing.T) {
	tests := []struct {
		name       string
		request    *Request
		forceHTTP2 bool
		want       ConnectionReusePolicy
	}{
		{
			name:    "plain request is safe",
			request: &Request{Path: []string{"{{BaseURL}}"}},
			want:    ReuseSafe,
		},
		{
			name:    "raw request without close is safe",
			request: &Request{Raw: []string{"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
			want:    ReuseSafe,
		},
		{
			name:    "race is unsafe",
			request: &Request{Race: true, RaceNumberRequests: 5},
			want:    ReuseUnsafe,
		},
		{
			// the pipeline client keeps its own connections, and a close would
			// cut off the other requests pipelined on it
			name:    "pipeline is safe",
			request: &Request{Pipeline: true},
			want:    ReuseSafe,
		},
		{
			name:    "raw connection close is unsafe",
			request: &Request{Raw: []string{"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nConnection: close\r\n\r\n"}},
			want:    ReuseUnsafe,
		},
		{
			name:    "header connection close is unsafe",
			request: &Request{Headers: map[string]string{"Connection": "close"}},
			want:    ReuseUnsafe,
		},
		{
			// time_delay measures the server-side window only, so HTTP/1.1 reuse is
			// measurement-safe and lets time-based fuzzing reuse connections.
			name:    "time_delay is safe under http1",
			request: &Request{Analyzer: &analyzers.AnalyzerTemplate{Name: "time_delay"}},
			want:    ReuseSafe,
		},
		{
			// Under HTTP/2 concurrent sleeping probes can multiplex and add jitter,
			// so fresh connections are required to keep detection error-free.
			name:       "time_delay is unsafe under http2",
			request:    &Request{Analyzer: &analyzers.AnalyzerTemplate{Name: "time_delay"}},
			forceHTTP2: true,
			want:       ReuseUnsafe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.request.AnalyzeConnectionReuse(tt.forceHTTP2))
		})
	}
}

const (
	rawGet    = "GET /x HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"
	rawTarget = "127.0.0.1:443"

	rawBaseURL       = "GET {{BaseURL}}/x HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"
	rawSelfContained = "GET http://other.test:8080/x HTTP/1.1\r\nHost: other.test\r\n\r\n"
)

// maySendElsewhereTests lists requests with whether they may leave the address
// of their target, https://127.0.0.1.
//
//nolint:exhaustruct,exhaustruct_v5,gochecknoglobals // a table in a function exceeds funlen
var maySendElsewhereTests = []struct {
	name    string
	request *Request
	want    bool
}{
	{name: "no requests", request: &Request{}},
	{name: "base url", request: &Request{Path: []string{"{{BaseURL}}"}}},
	{name: "base url path", request: &Request{Path: []string{"{{BaseURL}}/a1"}}},
	{name: "root url path", request: &Request{Path: []string{"{{RootURL}}/a1"}}},
	{name: "base url query", request: &Request{Path: []string{"{{BaseURL}}?a=1"}}},
	{name: "base url fragment", request: &Request{Path: []string{"{{BaseURL}}#a"}}},
	{name: "base url with a port", request: &Request{Path: []string{"{{BaseURL}}:8080/a"}}, want: true},
	{name: "root url with a port", request: &Request{Path: []string{"{{RootURL}}:8080/a"}}, want: true},
	{
		name:    "base url with a port variable",
		request: &Request{Path: []string{"{{BaseURL}}:{{port}}/a"}, Payloads: map[string]any{"port": []string{"8080"}}},
		want:    true,
	},
	{name: "base url with user info", request: &Request{Path: []string{"{{BaseURL}}@other.test/a"}}, want: true},
	{name: "base url that extends the host", request: &Request{Path: []string{"{{BaseURL}}.other.test/a"}}, want: true},
	{name: "host with a port", request: &Request{Path: []string{"http://{{Host}}:18081/"}}, want: true},
	{name: "absolute url", request: &Request{Path: []string{"http://other.test/"}}, want: true},
	{name: "hostname", request: &Request{Path: []string{"{{Hostname}}/a"}}, want: true},
	{
		name:    "one path of two sends elsewhere",
		request: &Request{Path: []string{"{{BaseURL}}/a2", "http://{{Host}}:18081/"}},
		want:    true,
	},
	{name: "raw request", request: &Request{Raw: []string{rawGet}}},
	{name: "raw with a host header", request: &Request{Raw: []string{"GET /x HTTP/1.1\r\nHost: other.test\r\n\r\n"}}},
	{name: "raw with a base url", request: &Request{Raw: []string{rawBaseURL}}},
	{
		// the host and port of an absolute request target are dropped
		name:    "raw with an absolute url",
		request: &Request{Raw: []string{"GET http://other.test:8080/x HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
	},
	{
		name:    "unsafe raw with an absolute url",
		request: &Request{Unsafe: true, Raw: []string{"GET http://other.test:8080/x HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
	},
	{
		name:    "raw with a host annotation",
		request: &Request{Raw: []string{"@Host: other.test:8080\r\n" + rawGet}},
		want:    true,
	},
	{
		name:    "raw with a host annotation among others",
		request: &Request{Raw: []string{"@timeout: 5s\r\n@Host: {{Hostname}}:18081\r\n" + rawGet}},
		want:    true,
	},
	{
		name:    "unsafe raw with a host annotation",
		request: &Request{Unsafe: true, Raw: []string{"@Host: other.test:8080\r\n" + rawGet}},
		want:    true,
	},
	{name: "raw with a sni annotation", request: &Request{Raw: []string{"@tls-sni: other.test\r\n" + rawGet}}},
	{
		// only the lines before the request line are annotations
		name:    "host annotation after the request line",
		request: &Request{Raw: []string{rawGet + "@Host: other.test:8080\r\n"}},
	},
	{
		name:    "one raw of two sends elsewhere",
		request: &Request{Raw: []string{rawGet, "@Host: other.test:8080\r\n" + rawGet}},
		want:    true,
	},
	{
		// the request line names the destination
		name:    "self-contained raw",
		request: &Request{SelfContained: true, Raw: []string{rawSelfContained}},
		want:    true,
	},
}

// TestMaySendElsewhere checks which requests may leave the address of their
// target, and that a request that does leave it is never reported as staying:
// each case also builds its requests for https://127.0.0.1 and compares where
// they go.
func TestMaySendElsewhere(t *testing.T) {
	t.Parallel()

	// compiling a request sets up global protocol state, so compile one at a time
	var compileMu sync.Mutex

	options := testutils.DefaultOptions

	for _, test := range maySendElsewhereTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Compile fills in the request, so each run compiles a copy
			request := *test.request

			compileMu.Lock()
			testutils.Init(options)

			info := &testutils.TemplateInfo{ID: "testing-elsewhere"} //nolint:exhaustruct,exhaustruct_v5 // only the id matters
			err := request.Compile(testutils.NewMockExecuterOptions(options, info))

			compileMu.Unlock()
			require.NoError(t, err)

			require.Equal(t, test.want, request.MaySendElsewhere())

			if request.SelfContained {
				return
			}

			for _, dest := range sentAddresses(t, &request) {
				if dest != rawTarget {
					require.True(t, request.MaySendElsewhere(), "a request goes to %s but is reported as staying", dest)
				}
			}
		})
	}
}

// sentAddresses returns the host and port each request of a compiled request
// block goes to for https://127.0.0.1.
func sentAddresses(t *testing.T, request *Request) []string {
	t.Helper()

	var addresses []string

	input := contextargs.NewWithInput(t.Context(), "https://127.0.0.1")
	generator := request.newGenerator(false)

	for {
		value, payloads, ok := generator.nextValue()
		if !ok {
			return addresses
		}

		generated, err := generator.Make(t.Context(), input, value, payloads, map[string]any{})
		require.NoError(t, err)

		sent, err := url.Parse(generated.URL())
		require.NoError(t, err)

		addresses = append(addresses, net.JoinHostPort(sent.Hostname(), portOf(sent)))
	}
}

// portOf returns the port u names, or the default port of its scheme.
func portOf(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}

	if u.Scheme == "http" {
		return "80"
	}

	return "443"
}
