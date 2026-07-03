package http

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
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
// must not reuse pooled keep-alive connections (race, pipeline, explicit
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
			name:    "pipeline is unsafe",
			request: &Request{Pipeline: true},
			want:    ReuseUnsafe,
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
