package templates_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	netHttp "net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

type resultIdentity struct {
	requestID  string
	probeIndex int
	path       string
}

func executeTemplateSource(t *testing.T, source, input string) []*output.ResultEvent {
	t.Helper()
	testutils.Init(testutils.DefaultOptions)
	executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
	t.Cleanup(executor.RateLimiter.Stop)

	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
	require.NoError(t, err)
	require.NoError(t, template.Executer.Compile())

	ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), input))
	ctx.OnResult = func(*output.InternalWrappedEvent) {}
	results, err := template.Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	return results
}

func identitiesOf(t *testing.T, results []*output.ResultEvent) []resultIdentity {
	t.Helper()
	identities := make([]resultIdentity, 0, len(results))
	for _, result := range results {
		identity := resultIdentity{requestID: result.RequestID, probeIndex: result.RequestProbeIndex}
		if parsed, err := url.Parse(result.Matched); err == nil && parsed.Scheme != "" {
			identity.path = parsed.Path
		}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		return fmt.Sprint(identities[i]) < fmt.Sprint(identities[j])
	})
	return identities
}

func newOKServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(netHttp.HandlerFunc(func(w netHttp.ResponseWriter, _ *netHttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestHTTPResultRequestIdentity(t *testing.T) {
	server := newOKServer(t)
	const source = `id: request-identity-http
info:
  name: Request identity http
  author: test
  severity: info
http:
  - id: login
    method: GET
    path:
      - "{{BaseURL}}/a?user={{user}}&nonce={{randstr}}"
      - "{{BaseURL}}/b?user={{user}}&nonce={{randstr}}"
    payloads:
      user:
        - alice
        - bob
    matchers:
      - type: word
        words:
          - ok
  - method: GET
    path:
      - "{{BaseURL}}/c?nonce={{randstr}}"
    matchers:
      - type: word
        words:
          - ok
`
	want := []resultIdentity{
		{requestID: "http_2", probeIndex: 1, path: "/c"},
		{requestID: "login", probeIndex: 1, path: "/a"},
		{requestID: "login", probeIndex: 1, path: "/a"},
		{requestID: "login", probeIndex: 2, path: "/b"},
		{requestID: "login", probeIndex: 2, path: "/b"},
	}

	first := executeTemplateSource(t, source, server.URL)
	second := executeTemplateSource(t, source, server.URL)

	require.Equal(t, want, identitiesOf(t, first), "payload iteration must not change the static path ordinal")
	require.Equal(t, identitiesOf(t, first), identitiesOf(t, second), "identity must be stable across runs")
	require.NotEqual(t, first[0].Matched, second[0].Matched, "runtime nonce must vary while identity stays fixed")
}

func TestHTTPSingleBlockWithoutIDUsesPositionalIdentity(t *testing.T) {
	server := newOKServer(t)
	const source = `id: request-identity-http-single
info:
  name: Request identity http single
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/only"
    matchers:
      - type: word
        words:
          - ok
`
	results := executeTemplateSource(t, source, server.URL)

	require.Equal(t, []resultIdentity{{requestID: "http_1", probeIndex: 1, path: "/only"}}, identitiesOf(t, results))

	encoded, err := json.Marshal(results[0])
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"request-id":"http_1"`)
	require.Contains(t, string(encoded), `"request-probe-index":1`)
	require.Contains(t, string(encoded), `"template-id":"request-identity-http-single"`)
}

func TestFlowResultRequestIdentityKeepsFlowSemantics(t *testing.T) {
	server := newOKServer(t)
	const source = `id: request-identity-flow
info:
  name: Request identity flow
  author: test
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/first"
    matchers:
      - type: word
        words:
          - ok
  - method: GET
    path:
      - "{{BaseURL}}/second"
    matchers:
      - type: word
        words:
          - ok
`
	results := executeTemplateSource(t, source, server.URL)

	require.Equal(t, []resultIdentity{
		{requestID: "http_1", probeIndex: 1, path: "/first"},
		{requestID: "http_2", probeIndex: 1, path: "/second"},
	}, identitiesOf(t, results))
}

func startLineServer(t *testing.T, reply string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
					return
				}
				_, _ = conn.Write([]byte(reply))
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func TestNetworkResultRequestIdentityDistinguishesHosts(t *testing.T) {
	firstAddress := startLineServer(t, "pong")
	secondAddress := startLineServer(t, "pong")
	source := fmt.Sprintf(`id: request-identity-tcp
info:
  name: Request identity tcp
  author: test
  severity: info
tcp:
  - host:
      - "{{Hostname}}"
      - "%s"
    inputs:
      - data: "ping\r\n"
    read-size: 8
    matchers:
      - type: word
        words:
          - pong
`, secondAddress)

	byHost := func(results []*output.ResultEvent) map[string]resultIdentity {
		identities := make(map[string]resultIdentity, len(results))
		for _, result := range results {
			identities[result.Matched] = resultIdentity{requestID: result.RequestID, probeIndex: result.RequestProbeIndex}
		}
		return identities
	}
	want := map[string]resultIdentity{
		firstAddress:  {requestID: "tcp_1", probeIndex: 1},
		secondAddress: {requestID: "tcp_1", probeIndex: 2},
	}

	require.Equal(t, want, byHost(executeTemplateSource(t, source, firstAddress)))
	require.Equal(t, want, byHost(executeTemplateSource(t, source, firstAddress)))
}

func TestSSLSiblingRequestBlocksHaveDistinctIdentity(t *testing.T) {
	server := httptest.NewTLSServer(netHttp.HandlerFunc(func(w netHttp.ResponseWriter, _ *netHttp.Request) {}))
	t.Cleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "https://")
	const source = `id: request-identity-ssl
info:
  name: Request identity ssl
  author: test
  severity: info
ssl:
  - address: "{{Host}}:{{Port}}"
    min_version: tls12
    max_version: tls12
    matchers:
      - type: dsl
        dsl:
          - 'tls_version == "tls12"'
  - address: "{{Host}}:{{Port}}"
    min_version: tls13
    max_version: tls13
    matchers:
      - type: dsl
        dsl:
          - 'tls_version == "tls13"'
`
	want := []resultIdentity{{requestID: "ssl_1"}, {requestID: "ssl_2"}}

	require.Equal(t, want, identitiesOf(t, executeTemplateSource(t, source, address)))
	require.Equal(t, want, identitiesOf(t, executeTemplateSource(t, source, address)))
}

func TestMultiProtocolResultRequestIdentity(t *testing.T) {
	server := newOKServer(t)
	address := startLineServer(t, "pong")
	source := fmt.Sprintf(`id: request-identity-multi
info:
  name: Request identity multi protocol
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/web"
    matchers:
      - type: word
        words:
          - ok
tcp:
  - host:
      - "%s"
    inputs:
      - data: "ping\r\n"
    read-size: 8
    matchers:
      - type: word
        words:
          - pong
`, address)

	results := executeTemplateSource(t, source, server.URL)

	got := map[string]int{}
	for _, result := range results {
		got[result.RequestID] = result.RequestProbeIndex
	}
	require.Equal(t, map[string]int{"http_1": 1, "tcp_1": 1}, got)
}
