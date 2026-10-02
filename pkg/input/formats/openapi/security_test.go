package openapi

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	httpTypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestGenerateRequestsSecurityAlternatives(t *testing.T) {
	for _, tc := range []struct {
		name, security string
		variables      map[string]interface{}
		wantCount      int
		wantAuth       string
		wantKey        string
	}{
		{"first alternative", `[{"oauth":[]},{"key":[]}]`, map[string]interface{}{"Authorization": "Bearer token"}, 1, "Bearer token", ""},
		{"second alternative", `[{"oauth":[]},{"key":[]}]`, map[string]interface{}{"X-API-Key": "key"}, 1, "", "key"},
		{"both alternatives available", `[{"oauth":[]},{"key":[]}]`, map[string]interface{}{"Authorization": "Bearer token", "X-API-Key": "key"}, 1, "Bearer token", ""},
		{"neither alternative available", `[{"oauth":[]},{"key":[]}]`, nil, 0, "", ""},
		{"combined complete", `[{"oauth":[],"key":[]}]`, map[string]interface{}{"Authorization": "Bearer token", "X-API-Key": "key"}, 1, "Bearer token", "key"},
		{"combined missing key", `[{"oauth":[],"key":[]}]`, map[string]interface{}{"Authorization": "Bearer token"}, 0, "", ""},
		{"combined missing token", `[{"oauth":[],"key":[]}]`, map[string]interface{}{"X-API-Key": "key"}, 0, "", ""},
		{"complete alternative after incomplete combined", `[{"oauth":[],"key":[]},{"key":[]}]`, map[string]interface{}{"X-API-Key": "key"}, 1, "", "key"},
		{"anonymous alternative first", `[{}, {"oauth":[]}]`, map[string]interface{}{"Authorization": "Bearer token"}, 1, "", ""},
		{"anonymous alternative last", `[{"oauth":[]},{}]`, nil, 1, "", ""},
		{"empty security list", `[]`, nil, 1, "", ""},
		{"unsupported alternative first", `[{"unsupported":[]},{"key":[]}]`, map[string]interface{}{"X-API-Key": "key"}, 1, "", "key"},
	} {
		for _, scope := range []string{"global", "operation"} {
			for _, skip := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/skip=%t", tc.name, scope, skip), func(t *testing.T) {
					global, operation := `"security":`+tc.security+`,`, ""
					if scope == "operation" {
						global, operation = "", global
					}
					document := fmt.Sprintf(`{
						"openapi":"3.0.3","info":{"title":"Security alternatives","version":"1"},
						"servers":[{"url":"https://example.com"}],
						"components":{"securitySchemes":{
							"oauth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://example.com/token","scopes":{}}}},
							"key":{"type":"apiKey","in":"header","name":"X-API-Key"},
							"unsupported":{"type":"http","scheme":"digest"}
						}},%s"paths":{"/protected":{"get":{%s"responses":{"200":{"description":"OK"}}}}}
					}`, global, operation)
					parser := New()
					parser.SetOptions(formats.InputFormatOptions{SkipFormatValidation: skip, Variables: tc.variables})
					var requests []*http.Request
					err := parser.Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
						req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rr.Request.Raw)))
						require.NoError(t, err)
						requests = append(requests, req)
						return false
					}, "")
					require.NoError(t, err)
					require.Len(t, requests, tc.wantCount)
					for _, req := range requests {
						defer req.Body.Close()
						require.Equal(t, tc.wantAuth, req.Header.Get("Authorization"))
						require.Equal(t, tc.wantKey, req.Header.Get("X-API-Key"))
					}
				})
			}
		}
	}
}

func TestGenerateRequestsOrdinaryParameterAuthDescription(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip=%t", skip), func(t *testing.T) {
			parser := New()
			parser.SetOptions(formats.InputFormatOptions{SkipFormatValidation: skip})
			const document = `{
				"openapi":"3.0.3","info":{"title":"Public operation","version":"1"},
				"servers":[{"url":"https://example.com"}],
				"paths":{"/public":{"get":{
					"parameters":[{"name":"display","in":"query","required":false,"description":"globalAuth","schema":{"type":"string","default":"compact"}}],
					"responses":{"200":{"description":"OK"}}
				}}}
			}`
			count := 0
			err := parser.Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
				count++
				require.Equal(t, "display=compact", rr.URL.RawQuery)
				return false
			}, "")
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}

func TestGenerateRequestsPublicOverrideUnsupportedGlobalSecurity(t *testing.T) {
	const document = `{
		"openapi":"3.0.3","info":{"title":"Public override","version":"1"},
		"servers":[{"url":"https://example.com"}],
		"components":{"securitySchemes":{"auth":{"type":"http","scheme":"digest"}}},
		"security":[{"auth":[]}],
		"paths":{"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}}}
	}`
	count := 0
	err := New().Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
		count++
		return false
	}, "")
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestSecuritySelectionMissingAndUnsupportedSchemes(t *testing.T) {
	schema := &openapi3.T{Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{
		"key":   {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-API-Key"}},
		"oauth": {Value: &openapi3.SecurityScheme{Type: "oauth2"}},
	}}}
	for _, tc := range []struct {
		name         string
		requirements openapi3.SecurityRequirements
		wantNames    []string
		wantError    bool
	}{
		{"missing combined credentials", openapi3.SecurityRequirements{{"oauth": nil, "key": nil}}, []string{"X-API-Key", "Authorization"}, false},
		{"first alternative diagnostics", openapi3.SecurityRequirements{{"oauth": nil}, {"key": nil}}, []string{"Authorization"}, false},
		{"unknown scheme", openapi3.SecurityRequirements{{"unknown": nil}}, nil, true},
		{"known and unknown in same object", openapi3.SecurityRequirements{{"key": nil, "unknown": nil}}, nil, true},
		{"known alternative after unknown", openapi3.SecurityRequirements{{"unknown": nil}, {"key": nil}}, []string{"X-API-Key"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := selectSecurityParameters(schema, &tc.requirements, nil)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var names []string
			for _, param := range params {
				names = append(names, param.Value.Name)
			}
			require.Equal(t, tc.wantNames, names)
		})
	}
	// Anonymous requirements do not need a components/securitySchemes section.
	params, err := GetGlobalParamsForSecurityRequirement(&openapi3.T{}, &openapi3.SecurityRequirements{{}})
	require.NoError(t, err)
	require.Empty(t, params)
}
