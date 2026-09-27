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

func TestGenerateRequestsWithSecuritySchemes(t *testing.T) {
	for _, test := range []struct {
		name     string
		scheme   string
		variable string
		value    string
		in       string
	}{
		{
			name: "oauth2", scheme: `{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://example.com/token","scopes":{"read":"Read access"}}}}`,
			variable: "Authorization", value: "Bearer supplied-token", in: "header",
		},
		{
			name: "openIdConnect", scheme: `{"type":"openIdConnect","openIdConnectUrl":"https://example.com/.well-known/openid-configuration"}`,
			variable: "Authorization", value: "Bearer supplied-token", in: "header",
		},
		{
			name: "bearer", scheme: `{"type":"http","scheme":"bearer"}`,
			variable: "Authorization", value: "Bearer supplied-token", in: "header",
		},
		{
			name: "basic", scheme: `{"type":"http","scheme":"basic"}`,
			variable: "Authorization", value: "Basic dXNlcjpwYXNz", in: "header",
		},
		{
			name: "apiKey-header", scheme: `{"type":"apiKey","name":"X-API-Key","in":"header"}`,
			variable: "X-API-Key", value: "supplied-key", in: "header",
		},
		{
			name: "apiKey-query", scheme: `{"type":"apiKey","name":"api_key","in":"query"}`,
			variable: "api_key", value: "supplied-key", in: "query",
		},
		{
			name: "apiKey-cookie", scheme: `{"type":"apiKey","name":"session","in":"cookie"}`,
			variable: "session", value: "supplied-key", in: "cookie",
		},
	} {
		for _, scope := range []string{"global", "operation"} {
			t.Run(test.name+"/"+scope, func(t *testing.T) {
				security := `"security":[{"auth":[]}],`
				if test.name == "oauth2" || test.name == "openIdConnect" {
					security = `"security":[{"auth":["read"]}],`
				}
				globalSecurity, operationSecurity := security, ""
				if scope == "operation" {
					globalSecurity, operationSecurity = "", security
				}
				document := fmt.Sprintf(`{
					"openapi":"3.0.3",
					"info":{"title":"Authentication test","version":"1.0"},
					"servers":[{"url":"https://example.com"}],
					"components":{"securitySchemes":{"auth":%s}},
					%s
					"paths":{"/protected":{"get":{%s"responses":{"200":{"description":"OK"}}}}}
				}`, test.scheme, globalSecurity, operationSecurity)
				parser := New()
				parser.SetOptions(formats.InputFormatOptions{
					RequiredOnly: true,
					Variables:    map[string]interface{}{test.variable: test.value},
				})
				var requests []*http.Request
				err := parser.Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
					req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rr.Request.Raw)))
					require.NoError(t, err)
					requests = append(requests, req)
					return false
				}, "")
				require.NoError(t, err)
				require.Len(t, requests, 1)
				req := requests[0]
				defer req.Body.Close()
				require.Equal(t, "/protected", req.URL.Path)
				switch test.in {
				case "header":
					require.Equal(t, test.value, req.Header.Get(test.variable))
				case "query":
					require.Equal(t, test.value, req.URL.Query().Get(test.variable))
				case "cookie":
					cookie, err := req.Cookie(test.variable)
					require.NoError(t, err)
					require.Equal(t, test.value, cookie.Value)
				}
			})
		}
	}
}

func TestGenerateRequestsOAuthOperationOverride(t *testing.T) {
	parser := New()
	parser.SetOptions(formats.InputFormatOptions{
		Variables: map[string]interface{}{
			"Authorization": "Bearer supplied-token",
			"X-API-Key":     "supplied-key",
		},
	})
	document := `{
		"openapi":"3.0.3",
		"info":{"title":"Authentication override test","version":"1.0"},
		"servers":[{"url":"https://example.com"}],
		"components":{"securitySchemes":{
			"oauth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://example.com/token","scopes":{}}}},
			"key":{"type":"apiKey","name":"X-API-Key","in":"header"}
		}},
		"security":[{"oauth":[]}],
		"paths":{
			"/protected":{"get":{"security":[{"key":[]}],"responses":{"200":{"description":"OK"}}}},
			"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}}
		}
	}`
	paths := make(map[string]bool)
	err := parser.Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
		paths[rr.URL.Path] = true
		key, _ := rr.Request.Headers.Get("X-Api-Key")
		if rr.URL.Path == "/protected" {
			require.Equal(t, "supplied-key", key)
		} else {
			require.Empty(t, key)
		}
		auth, _ := rr.Request.Headers.Get("Authorization")
		require.Empty(t, auth)
		return false
	}, "")
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"/protected": true, "/public": true}, paths)
}

func TestGenerateRequestsOAuthRequiresToken(t *testing.T) {
	for _, schemeType := range []string{"oauth2", "openIdConnect"} {
		t.Run(schemeType, func(t *testing.T) {
			param, err := GenerateParameterFromSecurityScheme(&openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{Type: schemeType},
			})
			require.NoError(t, err)
			var missing []string
			err = generateRequestsFromOp(&generateReqOptions{
				method:       http.MethodGet,
				pathURL:      "https://example.com",
				requestPath:  "/protected",
				op:           &openapi3.Operation{},
				globalParams: openapi3.Parameters{&openapi3.ParameterRef{Value: param}},
				missingParamValueCallback: func(param *openapi3.Parameter, _ *generateReqOptions) {
					missing = append(missing, param.Name)
				},
				callback: func(_ *httpTypes.RequestResponse) bool {
					t.Fatal("must not generate an authenticated request without a token")
					return false
				},
			})
			require.NoError(t, err)
			require.Equal(t, []string{"Authorization"}, missing)
		})
	}
}

func TestGenerateParameterUnsupportedSecurityScheme(t *testing.T) {
	_, err := GenerateParameterFromSecurityScheme(&openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{Type: "mutualTLS"},
	})
	require.ErrorContains(t, err, "unsupported security scheme type (mutualTLS)")
}
