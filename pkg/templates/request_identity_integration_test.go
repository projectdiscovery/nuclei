package templates_test

import (
	"bufio"
	"bytes"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

type resultIdentity struct {
	requestID  string
	probeIndex int
	path       string
}

type staticPreprocessor map[string]string

func (preprocessor staticPreprocessor) ProcessNReturnData(data []byte) ([]byte, map[string]interface{}) {
	replacements := make(map[string]interface{}, len(preprocessor))
	for expression, value := range preprocessor {
		data = bytes.ReplaceAll(data, []byte(expression), []byte(value))
		replacements[expression] = value
	}
	return data, replacements
}

func (preprocessor staticPreprocessor) Exists(data []byte) bool {
	for expression := range preprocessor {
		if bytes.Contains(data, []byte(expression)) {
			return true
		}
	}
	return false
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

func parseTemplateSourceWithPreprocessor(t *testing.T, source string, preprocessor templates.Preprocessor) *templates.Template {
	t.Helper()
	testutils.Init(testutils.DefaultOptions)
	executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
	t.Cleanup(executor.RateLimiter.Stop)
	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), preprocessor, executor)
	require.NoError(t, err)
	return template
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
	firstProbeIDs := probeIDsByMatchedPath(t, first)
	require.Equal(t, firstProbeIDs, probeIDsByMatchedPath(t, second))
	require.NotEqual(t, firstProbeIDs["/a"], firstProbeIDs["/b"])
	require.NotEmpty(t, firstProbeIDs["/c"])
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
	require.Contains(t, string(encoded), `"request-probe-id":"`+results[0].RequestProbeID+`"`)
	require.Contains(t, string(encoded), `"template-id":"request-identity-http-single"`)
	requireRuntimeStructuralRequestProbeID(t, "http", results[0].RequestProbeID)
}

func TestHTTPDuplicateExplicitIDsCompileWithStructuralIdentity(t *testing.T) {
	server := newOKServer(t)
	const source = `id: request-identity-http-duplicate-explicit
info:
  name: Request identity http duplicate explicit
  author: test
  severity: info
http:
  - id: login
    method: GET
    path:
      - "{{BaseURL}}/first"
    matchers:
      - type: word
        words:
          - ok
  - id: login
    method: GET
    path:
      - "{{BaseURL}}/second"
    matchers:
      - type: word
        words:
          - ok
`

	results := executeTemplateSource(t, source, server.URL)
	require.Len(t, results, 2)
	require.Equal(t, "login", results[0].RequestID)
	require.Equal(t, "login", results[1].RequestID)
	requireRuntimeStructuralRequestBlockID(t, "http", results[0].RequestBlockID)
	requireRuntimeStructuralRequestBlockID(t, "http", results[1].RequestBlockID)
	require.NotEqual(t, results[0].RequestBlockID, results[1].RequestBlockID)
	require.NotEqual(t, results[0].RequestProbeID, results[1].RequestProbeID)
}

func TestPreprocessedRequestBlockIDStableAcrossParses(t *testing.T) {
	testutils.Init(testutils.DefaultOptions)
	const source = `id: request-identity-preprocessor
info:
  name: Request identity preprocessor
  author: test
  severity: info
http:
  - method: POST
    path:
      - "{{BaseURL}}/{{randstr}}"
    body: {{randstr}}
    matchers:
      - type: word
        words:
          - ok
`
	parse := func() *templates.Template {
		executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
		t.Cleanup(executor.RateLimiter.Stop)
		template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
		require.NoError(t, err)
		return template
	}

	first := parse()
	second := parse()

	require.NotEqual(t, first.RequestsHTTP[0].Path, second.RequestsHTTP[0].Path)
	require.NotEqual(t, first.RequestsHTTP[0].Body, second.RequestsHTTP[0].Body)
	require.Equal(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, second.RequestsHTTP[0].RequestProbeIDs)
	requireRuntimeStructuralRequestBlockID(t, "http", first.RequestsHTTP[0].RequestBlockID)
	requireRuntimeStructuralRequestProbeID(t, "http", first.RequestsHTTP[0].RequestProbeIDs[0])
}

func TestTypedPreprocessorRequestIdentityParses(t *testing.T) {
	const source = `id: request-identity-typed-preprocessor
info:
  name: Request identity typed preprocessor
  author: test
  severity: info
http:
  - method: "{{method}}"
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - ok
`
	parse := func(method string) *templates.Template {
		return parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{method}}": method})
	}

	get := parse("GET")
	post := parse("POST")
	require.Equal(t, "GET", get.RequestsHTTP[0].Method.String())
	require.Equal(t, "POST", post.RequestsHTTP[0].Method.String())
	require.Equal(t, get.RequestsHTTP[0].RequestBlockID, post.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, get.RequestsHTTP[0].RequestProbeIDs, post.RequestsHTTP[0].RequestProbeIDs)
	requireRuntimeStructuralRequestBlockID(t, "http", get.RequestsHTTP[0].RequestBlockID)
	requireRuntimeStructuralRequestProbeID(t, "http", get.RequestsHTTP[0].RequestProbeIDs[0])
}

func TestPreprocessedExplicitRequestIDUsesStableSourceIdentity(t *testing.T) {
	const source = `id: request-identity-explicit-preprocessor
info:
  name: Request identity explicit preprocessor
  author: test
  severity: info
http:
  - id: "{{request_id}}"
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - ok
`
	first := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{request_id}}": "first"})
	second := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{request_id}}": "second"})

	require.Equal(t, "first", first.RequestsHTTP[0].ID)
	require.Equal(t, "second", second.RequestsHTTP[0].ID)
	require.Equal(t, "first", first.RequestsHTTP[0].RequestID)
	require.Equal(t, "second", second.RequestsHTTP[0].RequestID)
	require.Equal(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID)
	require.Contains(t, first.RequestsHTTP[0].RequestBlockID, ":explicit:nuclei_request_identity_")
	require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, second.RequestsHTTP[0].RequestProbeIDs)
}

func TestNestedPreprocessorRequestIdentityIsStable(t *testing.T) {
	const source = `id: request-identity-nested-preprocessor
info:
  name: Request identity nested preprocessor
  author: test
  severity: info
http:
  - path:
      - "{{BaseURL}}/"
    headers:
      X-Identity: "{{header_value}}"
    matchers:
      - type: word
        words:
          - ok
`
	first := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{header_value}}": "first"})
	second := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{header_value}}": "second"})

	require.Equal(t, "first", first.RequestsHTTP[0].Headers["X-Identity"])
	require.Equal(t, "second", second.RequestsHTTP[0].Headers["X-Identity"])
	require.Equal(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, second.RequestsHTTP[0].RequestProbeIDs)
}

func TestPreprocessedRequestIdentitySupportsAliasesAndJSON(t *testing.T) {
	t.Run("requests alias", func(t *testing.T) {
		const source = `id: request-identity-requests-alias
info:
  name: Request identity requests alias
  author: test
  severity: info
requests:
  - method: "{{method}}"
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - ok
`
		first := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{method}}": "GET"})
		second := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{method}}": "POST"})
		require.Equal(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID)
		require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, second.RequestsHTTP[0].RequestProbeIDs)
	})

	t.Run("network alias", func(t *testing.T) {
		const source = `id: request-identity-network-alias
info:
  name: Request identity network alias
  author: test
  severity: info
network:
  - host:
      - "{{Hostname}}"
    inputs:
      - data: "{{input}}"
    matchers:
      - type: word
        words:
          - ok
`
		first := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{input}}": "PING"})
		second := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{input}}": "PONG"})
		require.Equal(t, first.RequestsNetwork[0].RequestBlockID, second.RequestsNetwork[0].RequestBlockID)
		require.Equal(t, first.RequestsNetwork[0].RequestProbeIDs, second.RequestsNetwork[0].RequestProbeIDs)
	})

	t.Run("json", func(t *testing.T) {
		const source = `{
  "id": "request-identity-json",
  "info": {"name": "Request identity JSON", "author": "test", "severity": "info"},
  "http": [{
    "method": "{{method}}",
    "path": ["{{BaseURL}}/"],
    "matchers": [{"type": "word", "words": ["ok"]}]
  }]
}`
		first := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{method}}": "GET"})
		second := parseTemplateSourceWithPreprocessor(t, source, staticPreprocessor{"{{method}}": "POST"})
		require.Equal(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID)
		require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, second.RequestsHTTP[0].RequestProbeIDs)
	})
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
	requireRuntimeStructuralRequestBlockID(t, "http", results[0].RequestBlockID)
	requireRuntimeStructuralRequestBlockID(t, "http", results[1].RequestBlockID)
	require.NotEqual(t, results[0].RequestBlockID, results[1].RequestBlockID)
	for _, result := range results {
		requireRuntimeStructuralRequestProbeID(t, "http", result.RequestProbeID)
	}
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

	first := executeTemplateSource(t, source, firstAddress)
	second := executeTemplateSource(t, source, firstAddress)
	require.Equal(t, want, byHost(first))
	require.Equal(t, want, byHost(second))
	firstProbeIDs := map[string]string{}
	for _, result := range first {
		firstProbeIDs[result.Matched] = result.RequestProbeID
		requireRuntimeStructuralRequestProbeID(t, "tcp", result.RequestProbeID)
	}
	for _, result := range second {
		require.Equal(t, firstProbeIDs[result.Matched], result.RequestProbeID)
	}
	require.NotEqual(t, firstProbeIDs[firstAddress], firstProbeIDs[secondAddress])
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
	for _, result := range results {
		require.NotEmpty(t, result.RequestProbeID)
	}
}

func probeIDsByMatchedPath(t *testing.T, results []*output.ResultEvent) map[string]string {
	t.Helper()
	identities := make(map[string]string)
	for _, result := range results {
		parsed, err := url.Parse(result.Matched)
		require.NoError(t, err)
		if previous := identities[parsed.Path]; previous != "" {
			require.Equal(t, previous, result.RequestProbeID)
		}
		identities[parsed.Path] = result.RequestProbeID
		requireRuntimeStructuralRequestProbeID(t, result.Type, result.RequestProbeID)
	}
	return identities
}

func requireRuntimeStructuralRequestProbeID(t *testing.T, protocol, identity string) {
	t.Helper()
	prefix := "v1:" + protocol + ":probe-sha256:"
	require.True(t, strings.HasPrefix(identity, prefix), identity)
	require.Len(t, strings.TrimPrefix(identity, prefix), 64)
}

type memberIdentity struct {
	templateID string
	requestID  string
	probeIndex int
	path       string
}

func executeClusteredTemplateSources(t *testing.T, input string, sources ...string) []*output.ResultEvent {
	t.Helper()
	testutils.Init(testutils.DefaultOptions)
	parsed := make([]*templates.Template, 0, len(sources))
	for _, source := range sources {
		executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
		t.Cleanup(executor.RateLimiter.Stop)
		template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
		require.NoError(t, err)
		parsed = append(parsed, template)
	}

	clusterOptions := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
	t.Cleanup(clusterOptions.RateLimiter.Stop)
	clustered, clusteredCount, _ := templates.ClusterTemplates(parsed, clusterOptions)
	require.Len(t, clustered, 1, "sources must share one cluster")
	require.Equal(t, len(sources), clusteredCount)
	require.IsType(t, &templates.ClusterExecuter{}, clustered[0].Executer)

	ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), input))
	ctx.OnResult = func(*output.InternalWrappedEvent) {}
	results, err := clustered[0].Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	return results
}

func memberIdentitiesOf(results []*output.ResultEvent) []memberIdentity {
	identities := make([]memberIdentity, 0, len(results))
	for _, result := range results {
		identity := memberIdentity{templateID: result.TemplateID, requestID: result.RequestID, probeIndex: result.RequestProbeIndex}
		if parsed, err := urlutil.Parse(result.Matched); err == nil {
			identity.path = parsed.Path
		}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		a, b := identities[i], identities[j]
		if a.templateID != b.templateID {
			return a.templateID < b.templateID
		}
		return a.probeIndex < b.probeIndex
	})
	return identities
}

func TestClusteredResultsKeepMemberRequestIdentity(t *testing.T) {
	server := newOKServer(t)
	const explicitID = `id: member-identity-explicit
info:
  name: Member identity explicit
  author: test
  severity: info
http:
  - id: probe
    method: GET
    path:
      - "{{BaseURL}}/x"
      - "{{BaseURL}}/y"
    matchers:
      - type: word
        words:
          - ok
`
	const positional = `id: member-identity-positional
info:
  name: Member identity positional
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
      - "{{BaseURL}}/y"
    matchers:
      - type: word
        words:
          - ok
`
	want := []memberIdentity{
		{templateID: "member-identity-explicit", requestID: "probe", probeIndex: 1, path: "/x"},
		{templateID: "member-identity-explicit", requestID: "probe", probeIndex: 2, path: "/y"},
		{templateID: "member-identity-positional", requestID: "http_1", probeIndex: 1, path: "/x"},
		{templateID: "member-identity-positional", requestID: "http_1", probeIndex: 2, path: "/y"},
	}

	first := executeClusteredTemplateSources(t, server.URL, explicitID, positional)
	second := executeClusteredTemplateSources(t, server.URL, explicitID, positional)

	require.Equal(t, want, memberIdentitiesOf(first), "each member keeps its own request identity inside the cluster")
	require.Equal(t, memberIdentitiesOf(first), memberIdentitiesOf(second), "clustered identity must be stable across runs")
	probeIDs := func(results []*output.ResultEvent) map[string]string {
		identities := make(map[string]string, len(results))
		for _, result := range results {
			parsed, err := urlutil.Parse(result.Matched)
			require.NoError(t, err)
			identities[result.TemplateID+"|"+parsed.Path] = result.RequestProbeID
		}
		return identities
	}
	firstProbeIDs := probeIDs(first)
	require.Equal(t, firstProbeIDs, probeIDs(second))
	require.NotEqual(t, firstProbeIDs["member-identity-explicit|/x"], firstProbeIDs["member-identity-explicit|/y"])
	require.NotEqual(t, firstProbeIDs["member-identity-explicit|/x"], firstProbeIDs["member-identity-positional|/x"])

	for _, result := range first {
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"template-id":"`+result.TemplateID+`"`)
		require.Contains(t, string(encoded), `"request-id":"`+result.RequestID+`"`)
		require.Contains(t, string(encoded), `"request-block-id":"`+result.RequestBlockID+`"`)
		require.Contains(t, string(encoded), `"request-probe-id":"`+result.RequestProbeID+`"`)
		requireRuntimeStructuralRequestProbeID(t, "http", result.RequestProbeID)
		require.NotContains(t, string(encoded), `"template-id":"cluster-`, "cluster id must not leak into member results")
		switch result.TemplateID {
		case "member-identity-explicit":
			require.Equal(t, "v1:http:explicit:probe", result.RequestBlockID)
		case "member-identity-positional":
			requireRuntimeStructuralRequestBlockID(t, "http", result.RequestBlockID)
		}
	}
}

func executeOfflineTemplateSource(t *testing.T, source, rawResponse string) []*output.ResultEvent {
	t.Helper()
	testutils.Init(testutils.DefaultOptions)
	options := testutils.DefaultOptions.Copy()
	options.OfflineHTTP = true
	executor := testutils.NewMockExecuterOptions(options, nil)
	t.Cleanup(executor.RateLimiter.Stop)

	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
	require.NoError(t, err)

	parsedURL, err := urlutil.ParseAbsoluteURL("http://offline.test/index", false)
	require.NoError(t, err)
	input := contextargs.NewWithInput(context.Background(), parsedURL.String())
	input.MetaInput.ReqResp = &types.RequestResponse{URL: *parsedURL, Response: &types.HttpResponse{Raw: rawResponse}}

	ctx := scan.NewScanContext(context.Background(), input)
	ctx.OnResult = func(*output.InternalWrappedEvent) {}
	results, err := template.Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	return results
}

func TestOfflineHTTPResultsKeepRequestIdentity(t *testing.T) {
	const source = `id: offline-identity
info:
  name: Offline identity
  author: test
  severity: info
http:
  - id: home
    method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - hello
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - hello
`
	const rawResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"

	results := executeOfflineTemplateSource(t, source, rawResponse)

	got := make([]string, 0, len(results))
	for _, result := range results {
		require.Equal(t, "offline-identity", result.TemplateID)
		require.Equal(t, "offline-http", result.Type)
		require.Zero(t, result.RequestProbeIndex, "offline matching replays no template probe")
		require.Empty(t, result.RequestProbeID, "offline matching replays no template probe")
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"request-id":"`+result.RequestID+`"`)
		require.NotContains(t, string(encoded), "request-probe-index", "unset probe index must stay out of legacy-shaped output")
		require.NotContains(t, string(encoded), "request-probe-id", "unset probe identity must stay out of legacy-shaped output")
		got = append(got, result.RequestID)
		if result.RequestID == "home" {
			require.Equal(t, "v1:http:explicit:home", result.RequestBlockID)
		} else {
			requireRuntimeStructuralRequestBlockID(t, "http", result.RequestBlockID)
		}
	}
	sort.Strings(got)
	require.Equal(t, []string{"home", "http_2"}, got)
}

func TestRawRequestsSharingRequestLineHaveStableProbeIdentity(t *testing.T) {
	server := newOKServer(t)
	const source = `id: raw-identity
info:
  name: Raw identity
  author: test
  severity: info
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=admin
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=password
    matchers:
      - type: word
        words:
          - ok
`
	testutils.Init(testutils.DefaultOptions)
	executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
	executor.ExportReqURLPattern = true
	t.Cleanup(executor.RateLimiter.Stop)
	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
	require.NoError(t, err)

	ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), server.URL))
	ctx.OnResult = func(*output.InternalWrappedEvent) {}
	results, err := template.Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.Equal(t, "/login", results[0].ReqURLPattern)
	require.Equal(t, results[0].ReqURLPattern, results[1].ReqURLPattern, "url pattern cannot tell the raw probes apart")
	require.Equal(t, results[0].Matched, results[1].Matched, "matched url cannot tell the raw probes apart")
	probes := []int{results[0].RequestProbeIndex, results[1].RequestProbeIndex}
	sort.Ints(probes)
	require.Equal(t, []int{1, 2}, probes)
	require.NotEqual(t, results[0].RequestProbeID, results[1].RequestProbeID, "the full raw probe definition must separate requests sharing a URL")
	for _, result := range results {
		require.Equal(t, "http_1", result.RequestID)
		requireRuntimeStructuralRequestProbeID(t, "http", result.RequestProbeID)
	}
}

func TestGlobalMatcherResultsKeepOriginatingProbeIndex(t *testing.T) {
	server := newOKServer(t)
	const globalSource = `id: global-identity
info:
  name: Global identity
  author: test
  severity: info
http:
  - id: passive
    global-matchers: true
    matchers:
      - type: word
        words:
          - ok
`
	const source = `id: global-identity-origin
info:
  name: Global identity origin
  author: test
  severity: info
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=admin
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=password
`
	testutils.Init(testutils.DefaultOptions)
	executor := testutils.NewMockExecuterOptions(testutils.DefaultOptions, nil)
	executor.GlobalMatchers = globalmatchers.New()
	executor.ExportReqURLPattern = true
	t.Cleanup(executor.RateLimiter.Stop)

	globalTemplate, err := templates.ParseTemplateFromReader(strings.NewReader(globalSource), nil, executor)
	require.NoError(t, err)
	executor.GlobalMatchers.AddOperator(&globalmatchers.Item{
		TemplateID:   globalTemplate.ID,
		TemplateInfo: globalTemplate.Info,
		Operators:    globalTemplate.RequestsHTTP[0].GetCompiledOperators(),
	})

	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
	require.NoError(t, err)
	ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), server.URL))
	ctx.OnResult = func(*output.InternalWrappedEvent) {}
	results, err := template.Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2)

	probes := []int{results[0].RequestProbeIndex, results[1].RequestProbeIndex}
	sort.Ints(probes)
	require.Equal(t, []int{1, 2}, probes)
	probeIDs := []string{results[0].RequestProbeID, results[1].RequestProbeID}
	require.NotEqual(t, probeIDs[0], probeIDs[1])
	for _, result := range results {
		require.Equal(t, "global-identity", result.TemplateID)
		require.Equal(t, "passive", result.RequestID)
		require.Equal(t, "v1:http:explicit:passive", result.RequestBlockID)
		require.True(t, result.GlobalMatchers)
		require.Equal(t, "/login", result.ReqURLPattern)
		requireRuntimeStructuralRequestProbeID(t, "http", result.RequestProbeID)
	}
}

func requireRuntimeStructuralRequestBlockID(t *testing.T, protocol, identity string) {
	t.Helper()
	prefix := "v1:" + protocol + ":sha256:"
	require.True(t, strings.HasPrefix(identity, prefix), identity)
	require.Len(t, strings.TrimPrefix(identity, prefix), 64)
}
