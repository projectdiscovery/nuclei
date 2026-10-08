package openapi

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
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
	for _, skipValidation := range []bool{false, true} {
		for _, schemeType := range []string{"oauth2", "openIdConnect"} {
			t.Run(fmt.Sprintf("%s/skip-validation=%t", schemeType, skipValidation), func(t *testing.T) {
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
					opts:         formats.InputFormatOptions{SkipFormatValidation: skipValidation},
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
}

func oauthSecurityDocument(paths string) string {
	return fmt.Sprintf(`{
		"openapi":"3.0.3",
		"info":{"title":"Authentication scope test","version":"1.0"},
		"servers":[{"url":"https://example.com"}],
		"components":{"securitySchemes":{
			"oauth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://example.com/token","scopes":{}}}},
			"key":{"type":"apiKey","name":"X-API-Key","in":"header"}
		}},
		"security":[{"oauth":[]}],
		"paths":{%s}
	}`, paths)
}

func TestGenerateRequestsOAuthWithoutGlobalToken(t *testing.T) {
	for _, skipValidation := range []bool{true, false} {
		for _, test := range []struct {
			name  string
			paths string
			want  []string
		}{
			{
				name:  "public-only",
				paths: `"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}}`,
				want:  []string{"/public"},
			},
			{
				name: "mixed-security",
				paths: `
					"/protected":{"get":{"responses":{"200":{"description":"OK"}}}},
					"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}},
					"/key":{"get":{"security":[{"key":[]}],"responses":{"200":{"description":"OK"}}}}
				`,
				want: []string{"/public", "/key"},
			},
		} {
			t.Run(fmt.Sprintf("%s/skip-validation=%t", test.name, skipValidation), func(t *testing.T) {
				parser := New()
				parser.SetOptions(formats.InputFormatOptions{
					SkipFormatValidation: skipValidation,
					Variables:            map[string]interface{}{"X-API-Key": "supplied-key"},
				})
				var paths []string
				err := parser.Parse(strings.NewReader(oauthSecurityDocument(test.paths)), func(rr *httpTypes.RequestResponse) bool {
					paths = append(paths, rr.URL.Path)
					auth, _ := rr.Request.Headers.Get("Authorization")
					require.Empty(t, auth)
					key, _ := rr.Request.Headers.Get("X-Api-Key")
					if rr.URL.Path == "/key" {
						require.Equal(t, "supplied-key", key)
					} else {
						require.Empty(t, key)
					}
					return false
				}, "")
				require.NoError(t, err)
				require.ElementsMatch(t, test.want, paths)
			})
		}
	}
}

func TestGenerateRequestsOAuthMissingTokenCLI(t *testing.T) {
	const helperEnv = "NUCLEI_TEST_OPENAPI_MISSING_TOKEN"
	if os.Getenv(helperEnv) == "1" {
		config.CurrentAppMode = config.AppModeCLI
		document := oauthSecurityDocument(`
			"/protected/{id}":{"get":{
				"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
				"responses":{"200":{"description":"OK"}}
			}},
			"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}}
		`)
		err := New().Parse(strings.NewReader(document), func(rr *httpTypes.RequestResponse) bool {
			fmt.Println("generated:", rr.URL.Path)
			return false
		}, "")
		require.NoError(t, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGenerateRequestsOAuthMissingTokenCLI$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Dir = t.TempDir()
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode())
	require.Contains(t, string(output), "generated: /public")
	require.NotContains(t, string(output), "generated: /protected")
	parameters, err := os.ReadFile(filepath.Join(cmd.Dir, formats.DefaultVarDumpFileName))
	require.NoError(t, err)
	require.Contains(t, string(parameters), "Authorization=")
	require.Contains(t, string(parameters), "id=")
}

func TestGenerateRequestsCredentials(t *testing.T) {
	for _, auth := range []struct {
		scheme   string
		variable string
	}{
		{scheme: "oauth", variable: "Authorization"},
		{scheme: "key", variable: "X-API-Key"},
	} {
		for _, scope := range []string{"global", "operation"} {
			for _, skipValidation := range []bool{false, true} {
				for _, credential := range []struct {
					name          string
					present       bool
					value         interface{}
					wantProtected bool
				}{
					{name: "absent"},
					{name: "nil", present: true},
					{name: "empty", present: true, value: ""},
					{name: "supplied", present: true, value: "opaque-token", wantProtected: true},
				} {
					t.Run(fmt.Sprintf("%s/%s/%s/skip-validation=%t", auth.scheme, scope, credential.name, skipValidation), func(t *testing.T) {
						document := oauthSecurityDocument(`
							"/protected":{"get":{"responses":{"200":{"description":"OK"}}}},
							"/public":{"get":{"security":[],"responses":{"200":{"description":"OK"}}}}
						`)
						schema, err := openapi3.NewLoader().LoadFromData([]byte(document))
						require.NoError(t, err)
						security := openapi3.SecurityRequirements{{auth.scheme: []string{}}}
						if scope == "global" {
							schema.Security = security
						} else {
							schema.Security = nil
							schema.Paths.Map()["/protected"].Get.Security = &security
						}
						variables := map[string]interface{}{}
						if credential.present {
							variables[auth.variable] = credential.value
						}
						var paths []string
						err = GenerateRequestsFromSchema(schema, formats.InputFormatOptions{
							Variables:            variables,
							SkipFormatValidation: skipValidation,
						}, func(rr *httpTypes.RequestResponse) bool {
							paths = append(paths, rr.URL.Path)
							for _, header := range []string{"Authorization", "X-API-Key"} {
								value, _ := rr.Request.Headers.Get(http.CanonicalHeaderKey(header))
								if rr.URL.Path == "/protected" && header == auth.variable && credential.wantProtected {
									require.Equal(t, credential.value, value)
								} else {
									require.Empty(t, value)
								}
							}
							return false
						})
						require.NoError(t, err)
						wantPaths := []string{"/public"}
						if credential.wantProtected {
							wantPaths = append(wantPaths, "/protected")
						}
						require.ElementsMatch(t, wantPaths, paths)
					})
				}
			}
		}
	}
}

func TestGenerateParameterUnsupportedSecurityScheme(t *testing.T) {
	_, err := GenerateParameterFromSecurityScheme(&openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{Type: "mutualTLS"},
	})
	require.ErrorContains(t, err, "unsupported security scheme type (mutualTLS)")
}
