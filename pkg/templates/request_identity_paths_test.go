package templates_test

import (
	"context"
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

	for _, result := range first {
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"template-id":"`+result.TemplateID+`"`)
		require.Contains(t, string(encoded), `"request-id":"`+result.RequestID+`"`)
		require.NotContains(t, string(encoded), `"template-id":"cluster-`, "cluster id must not leak into member results")
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
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"request-id":"`+result.RequestID+`"`)
		require.NotContains(t, string(encoded), "request-probe-index", "unset probe index must stay out of legacy-shaped output")
		got = append(got, result.RequestID)
	}
	sort.Strings(got)
	require.Equal(t, []string{"home", "http_2"}, got)
}

func TestRawRequestsSharingRequestLineNeedProbeIndex(t *testing.T) {
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
	require.Equal(t, []int{1, 2}, probes, "probe index is the only field separating the raw probes")
	for _, result := range results {
		require.Equal(t, "http_1", result.RequestID)
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
	for _, result := range results {
		require.Equal(t, "global-identity", result.TemplateID)
		require.Equal(t, "passive", result.RequestID)
		require.True(t, result.GlobalMatchers)
		require.Equal(t, "/login", result.ReqURLPattern)
	}
}
