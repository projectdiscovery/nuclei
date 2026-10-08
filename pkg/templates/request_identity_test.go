package templates

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
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
		RequestsSSL:        []*ssl.Request{{Address: "{{Host}}:443"}, {Address: "{{Host}}:8443"}, {Address: "{{Host}}:9443"}, {Address: "{{Host}}:10443"}},
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

func requireStructuralRequestProbeID(t *testing.T, protocol, identity string) {
	t.Helper()
	prefix := "v1:" + protocol + ":probe-sha256:"
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

func TestRequestBlockIDUsesStructuralIdentityForDuplicateExplicitIDs(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{
		{ID: "login", Path: []string{"{{BaseURL}}/first"}},
		{ID: "login", Path: []string{"{{BaseURL}}/first"}},
		{ID: "login", Path: []string{"{{BaseURL}}/second"}},
		{ID: "status", Path: []string{"{{BaseURL}}/status"}},
	}}

	require.NoError(t, template.assignRequestBlockIDs())
	requireStructuralRequestBlockID(t, "http", template.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, template.RequestsHTTP[0].RequestBlockID, template.RequestsHTTP[1].RequestBlockID)
	require.NotEqual(t, template.RequestsHTTP[0].RequestBlockID, template.RequestsHTTP[2].RequestBlockID)
	require.Equal(t, "v1:http:explicit:status", template.RequestsHTTP[3].RequestBlockID)
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

func TestHTTPPathProbeIDsSurviveReorderAndInsertion(t *testing.T) {
	first := &Template{RequestsHTTP: []*http.Request{{
		Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPGet},
		Path:   []string{"{{BaseURL}}/a", "{{BaseURL}}/b"},
	}}}
	second := &Template{RequestsHTTP: []*http.Request{{
		Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPGet},
		Path:   []string{"{{BaseURL}}/b", "{{BaseURL}}/new", "{{BaseURL}}/a"},
	}}}

	require.NoError(t, first.assignRequestBlockIDs())
	require.NoError(t, second.assignRequestBlockIDs())

	firstByPath := probeIDsByValue(first.RequestsHTTP[0].Path, first.RequestsHTTP[0].RequestProbeIDs)
	secondByPath := probeIDsByValue(second.RequestsHTTP[0].Path, second.RequestsHTTP[0].RequestProbeIDs)
	require.Equal(t, firstByPath["{{BaseURL}}/a"], secondByPath["{{BaseURL}}/a"])
	require.Equal(t, firstByPath["{{BaseURL}}/b"], secondByPath["{{BaseURL}}/b"])
	require.NotEqual(t, secondByPath["{{BaseURL}}/new"], secondByPath["{{BaseURL}}/a"])
	require.NotEqual(t, first.RequestsHTTP[0].RequestBlockID, second.RequestsHTTP[0].RequestBlockID, "the per-probe identity must remain stable even when the block identity changes")
	for _, identity := range second.RequestsHTTP[0].RequestProbeIDs {
		requireStructuralRequestProbeID(t, "http", identity)
	}
}

func TestHTTPRawProbeIDsSurviveReorderAndInsertion(t *testing.T) {
	firstRaw := "POST /same HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nfirst"
	secondRaw := "POST /same HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nsecond"
	newRaw := "POST /same HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nnew"
	first := &Template{RequestsHTTP: []*http.Request{{Raw: []string{firstRaw, secondRaw}}}}
	second := &Template{RequestsHTTP: []*http.Request{{Raw: []string{secondRaw, newRaw, firstRaw}}}}

	require.NoError(t, first.assignRequestBlockIDs())
	require.NoError(t, second.assignRequestBlockIDs())

	firstByRaw := probeIDsByValue(first.RequestsHTTP[0].Raw, first.RequestsHTTP[0].RequestProbeIDs)
	secondByRaw := probeIDsByValue(second.RequestsHTTP[0].Raw, second.RequestsHTTP[0].RequestProbeIDs)
	require.Equal(t, firstByRaw[firstRaw], secondByRaw[firstRaw])
	require.Equal(t, firstByRaw[secondRaw], secondByRaw[secondRaw])
	require.NotEqual(t, secondByRaw[newRaw], secondByRaw[firstRaw])
}

func TestNetworkHostProbeIDsSurviveReorderAndInsertion(t *testing.T) {
	first := &Template{RequestsNetwork: []*network.Request{{
		Address: []string{"{{Hostname}}", "tls://{{Hostname}}"},
		Inputs:  []*network.Input{{Data: "PING"}},
	}}}
	second := &Template{RequestsNetwork: []*network.Request{{
		Address: []string{"tls://{{Hostname}}", "{{Hostname}}:9000", "{{Hostname}}"},
		Inputs:  []*network.Input{{Data: "PING"}},
	}}}

	require.NoError(t, first.assignRequestBlockIDs())
	require.NoError(t, second.assignRequestBlockIDs())

	firstByHost := probeIDsByValue(first.RequestsNetwork[0].Address, first.RequestsNetwork[0].RequestProbeIDs)
	secondByHost := probeIDsByValue(second.RequestsNetwork[0].Address, second.RequestsNetwork[0].RequestProbeIDs)
	require.Equal(t, firstByHost["{{Hostname}}"], secondByHost["{{Hostname}}"])
	require.Equal(t, firstByHost["tls://{{Hostname}}"], secondByHost["tls://{{Hostname}}"])
	require.NotEqual(t, secondByHost["{{Hostname}}:9000"], secondByHost["{{Hostname}}"])
	for _, identity := range second.RequestsNetwork[0].RequestProbeIDs {
		requireStructuralRequestProbeID(t, "tcp", identity)
	}
}

func TestRequestProbeIDUsesProjectedBlockDefinition(t *testing.T) {
	first := &Template{RequestsHTTP: []*http.Request{{
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{"first"}}}},
		Method:    http.HTTPMethodTypeHolder{MethodType: http.HTTPPost},
		Path:      []string{"{{BaseURL}}/login"},
		Body:      "username={{username}}",
		Payloads:  map[string]interface{}{"username": []string{"alice"}},
	}}}
	changedEvidence := &Template{RequestsHTTP: []*http.Request{{
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{Regex: []string{"second"}}}},
		Method:    http.HTTPMethodTypeHolder{MethodType: http.HTTPPost},
		Path:      []string{"{{BaseURL}}/login"},
		Body:      "username={{username}}",
		Payloads:  map[string]interface{}{"username": []string{"bob"}},
	}}}
	changedCore := &Template{RequestsHTTP: []*http.Request{{
		Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPPost},
		Path:   []string{"{{BaseURL}}/login"},
		Body:   "account={{username}}",
	}}}

	require.NoError(t, first.assignRequestBlockIDs())
	require.NoError(t, changedEvidence.assignRequestBlockIDs())
	require.NoError(t, changedCore.assignRequestBlockIDs())
	require.Equal(t, first.RequestsHTTP[0].RequestProbeIDs, changedEvidence.RequestsHTTP[0].RequestProbeIDs)
	require.NotEqual(t, first.RequestsHTTP[0].RequestProbeIDs, changedCore.RequestsHTTP[0].RequestProbeIDs)
}

func probeIDsByValue(values, identities []string) map[string]string {
	result := make(map[string]string, len(values))
	for index, value := range values {
		result[value] = identities[index]
	}
	return result
}

func TestUnnamedRequestBlockIDIgnoresMatcherExtractorPayloadAndExecutionEdits(t *testing.T) {
	structured := func(word, regex, payload string, attack generators.AttackType, threads, redirects int) *http.Request {
		return &http.Request{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Name:  "detection",
					Words: []string{word},
				}},
				Extractors: []*extractors.Extractor{{
					Name:     "token",
					Internal: true,
					Regex:    []string{regex},
				}},
				MatchersCondition: "and",
			},
			Method:       http.HTTPMethodTypeHolder{MethodType: http.HTTPPost},
			Path:         []string{"{{BaseURL}}/login"},
			Body:         `username={{username}}`,
			Payloads:     map[string]interface{}{"username": []string{payload}},
			AttackType:   generators.AttackTypeHolder{Value: attack},
			Threads:      threads,
			MaxRedirects: redirects,
			Redirects:    redirects > 0,
			Unsafe:       redirects > 0,
		}
	}

	base := requestBlockIDForTest(t, structured("ok", `token=(.+)`, "alice", generators.BatteringRamAttack, 1, 0))
	changedRequest := structured("success", `session=(.+)`, "bob", generators.ClusterBombAttack, 20, 7)
	changedRequest.Matchers[0].Type = matchers.MatcherTypeHolder{MatcherType: matchers.RegexMatcher}
	changedRequest.Matchers[0].Words = nil
	changedRequest.Matchers[0].Regex = []string{`success-[0-9]+`}
	changedRequest.Matchers[0].Part = "header"
	changedRequest.Extractors[0].Type = extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor}
	changedRequest.Extractors[0].Regex = nil
	changedRequest.Extractors[0].JSON = []string{".session"}
	changed := requestBlockIDForTest(t, changedRequest)
	require.Equal(t, base, changed)

	differentPayloadKey := structured("ok", `token=(.+)`, "alice", generators.BatteringRamAttack, 1, 0)
	differentPayloadKey.Payloads = map[string]interface{}{"account": []string{"alice"}}
	require.NotEqual(t, base, requestBlockIDForTest(t, differentPayloadKey))
}

func TestUnnamedRequestBlockIDRetainsOperatorRoles(t *testing.T) {
	request := func(matcherName string, matcherInternal, extractorInternal bool) *http.Request {
		return &http.Request{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{Name: matcherName, Internal: matcherInternal}},
				Extractors: []*extractors.Extractor{{
					Name:     "token",
					Internal: extractorInternal,
				}},
			},
			Path: []string{"{{BaseURL}}/login"},
		}
	}

	base := requestBlockIDForTest(t, request("detection", false, true))
	require.NotEqual(t, base, requestBlockIDForTest(t, request("alternate", false, true)))
	require.NotEqual(t, base, requestBlockIDForTest(t, request("detection", true, true)))
	require.NotEqual(t, base, requestBlockIDForTest(t, request("detection", false, false)))
}

func TestUnnamedRequestBlockIDChangesWithCoreProbeDefinition(t *testing.T) {
	structured := func(method http.HTTPMethodType, path, body string) *http.Request {
		return &http.Request{
			Method: http.HTTPMethodTypeHolder{MethodType: method},
			Path:   []string{path},
			Body:   body,
		}
	}

	base := requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/a", "alpha"))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPPost, "{{BaseURL}}/a", "alpha")))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/b", "alpha")))
	require.NotEqual(t, base, requestBlockIDForTest(t, structured(http.HTTPGet, "{{BaseURL}}/a", "beta")))

	rawBase := &http.Request{Raw: []string{"POST /login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nalpha"}}
	rawChanged := &http.Request{Raw: []string{"POST /login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\nbeta"}}
	require.NotEqual(t, requestBlockIDForTest(t, rawBase), requestBlockIDForTest(t, rawChanged))
}

func TestProjectedUnnamedRequestBlockIDCollisionFallsBackToFullDefinition(t *testing.T) {
	request := func(word string) *http.Request {
		return &http.Request{
			Operators: operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{word}}}},
			Path:      []string{"{{BaseURL}}/same"},
		}
	}
	template := &Template{RequestsHTTP: []*http.Request{request("first"), request("second")}}

	require.NoError(t, template.assignRequestBlockIDs())
	require.NotEqual(t, template.RequestsHTTP[0].RequestBlockID, template.RequestsHTTP[1].RequestBlockID)
	require.Equal(t, fullRequestBlockIDForTest(t, template.RequestsHTTP[0]), template.RequestsHTTP[0].RequestBlockID)
	require.Equal(t, fullRequestBlockIDForTest(t, template.RequestsHTTP[1]), template.RequestsHTTP[1].RequestBlockID)
	require.NotEqual(t, template.RequestsHTTP[0].RequestProbeIDs, template.RequestsHTTP[1].RequestProbeIDs)
}

func TestIdenticalUnnamedRequestBlocksShareIdentity(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{
		{Path: []string{"{{BaseURL}}/same"}},
		{Path: []string{"{{BaseURL}}/same"}},
	}}

	require.NoError(t, template.assignRequestBlockIDs())
	require.Equal(t, template.RequestsHTTP[0].RequestBlockID, template.RequestsHTTP[1].RequestBlockID)
	require.Equal(t, template.RequestsHTTP[0].RequestProbeIDs, template.RequestsHTTP[1].RequestProbeIDs)
}

func TestRequestBlockIDCrossProtocolStabilityAndProbeChanges(t *testing.T) {
	stable := []struct {
		name   string
		first  protocols.Request
		second protocols.Request
	}{
		{
			name:   "dns execution settings",
			first:  &dns.Request{Name: "{{FQDN}}", Retries: 1, Resolvers: []string{"1.1.1.1"}},
			second: &dns.Request{Name: "{{FQDN}}", Retries: 5, Resolvers: []string{"8.8.8.8"}},
		},
		{
			name:   "file traversal settings",
			first:  &file.Request{Extensions: []string{"yaml"}, MaxSize: "1Mb"},
			second: &file.Request{Extensions: []string{"yaml"}, MaxSize: "10Mb", NoRecursive: true},
		},
		{
			name:   "network read settings",
			first:  &network.Request{Address: []string{"{{Hostname}}"}, Inputs: []*network.Input{{Data: "PING"}}, ReadSize: 1024},
			second: &network.Request{Address: []string{"{{Hostname}}"}, Inputs: []*network.Input{{Data: "PING"}}, ReadSize: 4096, ReadAll: true},
		},
		{
			name:   "ssl client implementation",
			first:  &ssl.Request{Address: "{{Host}}:443", ScanMode: "ctls"},
			second: &ssl.Request{Address: "{{Host}}:443", ScanMode: "ztls"},
		},
		{
			name:   "code precondition",
			first:  &code.Request{Engine: []string{"sh"}, Source: "whoami", PreCondition: "true"},
			second: &code.Request{Engine: []string{"sh"}, Source: "whoami", PreCondition: "false"},
		},
		{
			name: "javascript payload values",
			first: &javascript.Request{
				Code:       "Execute({{username}})",
				Payloads:   map[string]interface{}{"username": []string{"alice"}},
				Threads:    1,
				AttackType: generators.AttackTypeHolder{Value: generators.BatteringRamAttack},
			},
			second: &javascript.Request{
				Code:       "Execute({{username}})",
				Payloads:   map[string]interface{}{"username": []string{"bob"}},
				Threads:    10,
				AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
			},
		},
		{
			name:   "websocket payload values",
			first:  &websocket.Request{Address: "{{RootURL}}/socket", Payloads: map[string]interface{}{"message": []string{"one"}}},
			second: &websocket.Request{Address: "{{RootURL}}/socket", Payloads: map[string]interface{}{"message": []string{"two"}}},
		},
	}
	for _, test := range stable {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, requestBlockIDForTest(t, test.first), requestBlockIDForTest(t, test.second))
		})
	}

	changed := []struct {
		name   string
		first  protocols.Request
		second protocols.Request
	}{
		{name: "dns name", first: &dns.Request{Name: "{{FQDN}}"}, second: &dns.Request{Name: "api.{{FQDN}}"}},
		{name: "file extension", first: &file.Request{Extensions: []string{"yaml"}}, second: &file.Request{Extensions: []string{"json"}}},
		{name: "file denylist", first: &file.Request{Extensions: []string{"all"}, DenyList: []string{"png"}}, second: &file.Request{Extensions: []string{"all"}, DenyList: []string{"zip"}}},
		{name: "network input", first: &network.Request{Inputs: []*network.Input{{Data: "PING"}}}, second: &network.Request{Inputs: []*network.Input{{Data: "HELLO"}}}},
		{name: "ssl address", first: &ssl.Request{Address: "{{Host}}:443"}, second: &ssl.Request{Address: "{{Host}}:8443"}},
		{name: "code source", first: &code.Request{Source: "whoami"}, second: &code.Request{Source: "id"}},
		{name: "javascript code", first: &javascript.Request{Code: "ExecuteA()"}, second: &javascript.Request{Code: "ExecuteB()"}},
		{name: "websocket address", first: &websocket.Request{Address: "{{RootURL}}/a"}, second: &websocket.Request{Address: "{{RootURL}}/b"}},
		{name: "whois query", first: &whois.Request{Query: "{{FQDN}}"}, second: &whois.Request{Query: "example.com"}},
	}
	for _, test := range changed {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, requestBlockIDForTest(t, test.first), requestBlockIDForTest(t, test.second))
		})
	}
}

func TestExplicitRequestBlockIDIsDurableAcrossDefinitionChanges(t *testing.T) {
	first := &http.Request{ID: "login", Path: []string{"{{BaseURL}}/old"}}
	second := &http.Request{ID: "login", Path: []string{"{{BaseURL}}/new"}}

	require.Equal(t, "v1:http:explicit:login", requestBlockIDForTest(t, first))
	require.Equal(t, requestBlockIDForTest(t, first), requestBlockIDForTest(t, second))
}

func requestBlockIDForTest(t *testing.T, request protocols.Request) string {
	t.Helper()
	identity, err := requestBlockID(request)
	require.NoError(t, err)
	return identity
}

func fullRequestBlockIDForTest(t *testing.T, request protocols.Request) string {
	t.Helper()
	identity, err := fullStructuralRequestBlockID(request)
	require.NoError(t, err)
	return identity
}
