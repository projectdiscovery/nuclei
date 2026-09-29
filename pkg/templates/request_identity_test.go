package templates

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois"
	"github.com/stretchr/testify/require"
)

func TestAssignRequestOutputIDsCoversEveryProtocol(t *testing.T) {
	template := &Template{
		RequestsDNS:        []*dns.Request{{}},
		RequestsFile:       []*file.Request{{}},
		RequestsNetwork:    []*network.Request{{}},
		RequestsHTTP:       []*http.Request{{}},
		RequestsHeadless:   []*headless.Request{{}},
		RequestsSSL:        []*ssl.Request{{}, {}, {}, {}},
		RequestsWebsocket:  []*websocket.Request{{}},
		RequestsWHOIS:      []*whois.Request{{}},
		RequestsCode:       []*code.Request{{}},
		RequestsJavascript: []*javascript.Request{{ID: "explicit-js"}, {}},
	}

	require.NoError(t, template.assignRequestBlockIDs())
	template.assignRequestOutputIDs()

	require.Equal(t, "dns_1", template.RequestsDNS[0].RequestID)
	require.Equal(t, "file_1", template.RequestsFile[0].RequestID)
	require.Equal(t, "tcp_1", template.RequestsNetwork[0].RequestID)
	require.Equal(t, "http_1", template.RequestsHTTP[0].RequestID)
	require.Equal(t, "headless_1", template.RequestsHeadless[0].RequestID)
	require.Equal(t, "websocket_1", template.RequestsWebsocket[0].RequestID)
	require.Equal(t, "whois_1", template.RequestsWHOIS[0].RequestID)
	require.Equal(t, "code_1", template.RequestsCode[0].RequestID)
	for i, want := range []string{"ssl_1", "ssl_2", "ssl_3", "ssl_4"} {
		require.Equal(t, want, template.RequestsSSL[i].RequestID)
	}
	require.Equal(t, "explicit-js", template.RequestsJavascript[0].RequestID)
	require.Equal(t, "javascript_2", template.RequestsJavascript[1].RequestID)

	requireStructuralRequestBlockID(t, "dns", template.RequestsDNS[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "file", template.RequestsFile[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "tcp", template.RequestsNetwork[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "http", template.RequestsHTTP[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "headless", template.RequestsHeadless[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "websocket", template.RequestsWebsocket[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "whois", template.RequestsWHOIS[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "code", template.RequestsCode[0].RequestBlockID)
	for _, request := range template.RequestsSSL {
		requireStructuralRequestBlockID(t, "ssl", request.RequestBlockID)
	}
	require.Equal(t, "v1:javascript:explicit:explicit-js", template.RequestsJavascript[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "javascript", template.RequestsJavascript[1].RequestBlockID)

	for _, request := range template.RequestsSSL {
		require.Empty(t, request.ID, "output identity must not rewrite the template request id")
	}
}

func requireStructuralRequestBlockID(t *testing.T, protocol, identity string) {
	t.Helper()
	prefix := "v1:" + protocol + ":sha256:"
	require.True(t, strings.HasPrefix(identity, prefix), identity)
	digest := strings.TrimPrefix(identity, prefix)
	require.Len(t, digest, 64)
	_, err := hex.DecodeString(digest)
	require.NoError(t, err)
}

func TestAssignRequestOutputIDsIsRepeatable(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{{ID: "login"}, {}}}

	template.assignRequestOutputIDs()
	first := []string{template.RequestsHTTP[0].RequestID, template.RequestsHTTP[1].RequestID}
	template.assignRequestOutputIDs()

	require.Equal(t, []string{"login", "http_2"}, first)
	require.Equal(t, first, []string{template.RequestsHTTP[0].RequestID, template.RequestsHTTP[1].RequestID})
}

func TestRequestBlockIDSeparatesExplicitAndGeneratedRequestIDs(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{
		{ID: "http_2", Path: []string{"{{BaseURL}}/explicit"}},
		{Path: []string{"{{BaseURL}}/generated"}},
	}}

	require.NoError(t, template.assignRequestBlockIDs())
	template.validateAllRequestIDs()
	template.assignRequestOutputIDs()

	require.Equal(t, "http_2", template.RequestsHTTP[0].RequestID)
	require.Equal(t, "http_2", template.RequestsHTTP[1].RequestID)
	require.Equal(t, "v1:http:explicit:http_2", template.RequestsHTTP[0].RequestBlockID)
	requireStructuralRequestBlockID(t, "http", template.RequestsHTTP[1].RequestBlockID)
	require.NotEqual(t, template.RequestsHTTP[0].RequestBlockID, template.RequestsHTTP[1].RequestBlockID)
}

func TestRequestBlockIDRejectsDuplicateExplicitIDsWithinProtocol(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{{ID: "login"}, {ID: "login"}}}

	err := template.assignRequestBlockIDs()

	require.EqualError(t, err, `duplicate explicit http request id "login"`)
}

func TestRequestBlockIDAllowsSameExplicitIDAcrossProtocols(t *testing.T) {
	template := &Template{
		RequestsHTTP: []*http.Request{{ID: "probe"}},
		RequestsDNS:  []*dns.Request{{ID: "probe"}},
	}

	require.NoError(t, template.assignRequestBlockIDs())
	require.Equal(t, "v1:http:explicit:probe", template.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, "v1:dns:explicit:probe", template.RequestsDNS[0].RequestBlockID)
}

func TestUnnamedRequestBlockIDIsStableAcrossReordering(t *testing.T) {
	first := &Template{RequestsHTTP: []*http.Request{
		{Path: []string{"{{BaseURL}}/a"}},
		{Path: []string{"{{BaseURL}}/b"}},
	}}
	second := &Template{RequestsHTTP: []*http.Request{
		{Path: []string{"{{BaseURL}}/b"}},
		{Path: []string{"{{BaseURL}}/a"}},
	}}

	require.NoError(t, first.assignRequestBlockIDs())
	require.NoError(t, second.assignRequestBlockIDs())

	firstByPath := map[string]string{}
	for _, request := range first.RequestsHTTP {
		firstByPath[request.Path[0]] = request.RequestBlockID
	}
	for _, request := range second.RequestsHTTP {
		require.Equal(t, firstByPath[request.Path[0]], request.RequestBlockID)
	}
}

func TestUnnamedRequestBlockIDChangesWithSemanticDefinition(t *testing.T) {
	wordMatcher := func(word string) operators.Operators {
		return operators.Operators{Matchers: []*matchers.Matcher{{
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{word},
		}}}
	}
	structured := func(method http.HTTPMethodType, path, body, word string) *http.Request {
		return &http.Request{
			Operators: wordMatcher(word),
			Method:    http.HTTPMethodTypeHolder{MethodType: method},
			Path:      []string{path},
			Body:      body,
		}
	}

	base := requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/a", "alpha", "ok"))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPPost, "{{BaseURL}}/a", "alpha", "ok")))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/b", "alpha", "ok")))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/a", "beta", "ok")))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/a", "alpha", "changed")))

	rawBase := &http.Request{Raw: []string{"POST /login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nalpha"}}
	rawChanged := &http.Request{Raw: []string{"POST /login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nbeta"}}
	require.NotEqual(t, requestBlockIDForTest(t, rawBase), requestBlockIDForTest(t, rawChanged))
}

func TestExplicitRequestBlockIDIsDurableAcrossDefinitionChanges(t *testing.T) {
	first := &http.Request{ID: "login", Path: []string{"{{BaseURL}}/old"}}
	second := &http.Request{ID: "login", Path: []string{"{{BaseURL}}/new"}}

	require.Equal(t, "v1:http:explicit:login", requestBlockIDForTest(t, first))
	require.Equal(t, requestBlockIDForTest(t, first), requestBlockIDForTest(t, second))
}

func requestBlockIDForTest(t *testing.T, request *http.Request) string {
	t.Helper()
	identity, err := requestBlockID(request)
	require.NoError(t, err)
	return identity
}
