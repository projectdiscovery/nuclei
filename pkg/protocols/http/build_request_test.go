package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	urlutil "github.com/projectdiscovery/utils/url"
)

func TestMakeRequestFromModal(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}/login.php"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
		Body:   "username=test&password=pass",
		Headers: map[string]string{
			"Content-Type":   "application/x-www-form-urlencoded",
			"Content-Length": "1",
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	if req.request.URL == nil {
		t.Fatalf("url is nil in generator make")
	}
	bodyBytes, _ := req.request.BodyBytes()
	require.Equal(t, "/login.php", req.request.Path, "could not get correct request path")
	require.Equal(t, "username=test&password=pass", string(bodyBytes), "could not get correct request body")
}

func TestMakeRequestFromModalTrimSuffixSlash(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}?query=example"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com/test.php"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	require.Equal(t, "https://example.com/test.php?query=example", req.request.String(), "could not get correct request path")

	generator = request.newGenerator(false)
	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com/test/"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	require.Equal(t, "https://example.com/test/?query=example", req.request.String(), "could not get correct request path")
}

func TestMakeRequestFromRawWithPayloads(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:   templateID,
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

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic admin:admin", authorization, "could not get correct authorization headers from raw")

	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization = req.request.Header.Get("Authorization")
	require.Equal(t, "Basic admin:guest", authorization, "could not get correct authorization headers from raw")
}

func TestMakeRequestBodiesUseHTTPBody(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-http-body",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	requests := map[string]*Request{
		"raw": {
			ID: "testing-http-body",
			Raw: []string{`POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: text/plain

raw-body`},
		},
		"model": {
			ID:     "testing-http-body",
			Path:   []string{"{{BaseURL}}/"},
			Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
			Body:   "model-body",
		},
	}
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, request.Compile(executerOpts))
			generator := request.newGenerator(false)
			inputData, payloads, _ := generator.nextValue()
			req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
			require.NoError(t, err)

			// Library body setters copy the body several times over.
			require.IsType(t, &httpbody.Body{}, req.request.Body)
			body, err := io.ReadAll(req.request.Body)
			require.NoError(t, err)
			require.Equal(t, name+"-body", string(body))
			require.Equal(t, int64(len(body)), req.request.ContentLength)
		})
	}
}

func TestMakeRequestFromRawPayloadExpressions(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:   templateID,
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
Authorization: Basic {{base64(username + ':' + password)}}
Accept-Encoding: gzip`},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46YWRtaW4=", authorization, "could not get correct authorization headers from raw")

	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization = req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46Z3Vlc3Q=", authorization, "could not get correct authorization headers from raw")
}

func TestMakeUnsafeRequestFromRawWithHostAnnotation(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http-unsafe-annotations"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Unsafe: true,
		Raw: []string{`@Host: honey.scanme.sh
GET /foo HTTP/1.1
Host: {{Hostname}}`},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile unsafe raw request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	req, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "http://scanme.sh"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make unsafe http request")
	require.NotNil(t, req.rawRequest, "raw request should be present")
	require.NotContains(t, string(req.rawRequest.UnsafeRawBytes), "@Host:", "unsafe raw request bytes should not contain annotation lines")

	parsedURL, parseErr := urlutil.ParseAbsoluteURL(req.rawRequest.FullURL, true)
	require.Nil(t, parseErr, "could not parse generated unsafe request URL")
	require.Equal(t, "honey.scanme.sh", parsedURL.Host, "host should be overridden by @Host annotation in unsafe mode")
	require.Equal(t, "http", parsedURL.Scheme, "scheme should inherit from input when annotation host has no scheme")
}

func TestUnsafeRawRequestPreservesAbsoluteRequestTarget(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	const requestLine = "GET http://intranet/foo?request=1 HTTP/1.1"
	request := &Request{
		ID:     "testing-http-unsafe-absolute-request-target",
		Name:   "testing",
		Unsafe: true,
		Raw: []string{requestLine + `
Host: {{Hostname}}`},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts), "could not compile unsafe raw request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	generated, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "http://example.com/bar?input=1"), inputData, payloads, map[string]interface{}{})
	require.NoError(t, err, "could not make unsafe raw request")
	generatedURL, err := urlutil.ParseAbsoluteURL(generated.URL(), true)
	require.NoError(t, err, "could not parse generated request URL")
	require.Equal(t, "example.com", generatedURL.Host, "absolute request target must not override the scan target")
	require.Equal(t, "/foo", generatedURL.Path, "absolute request target path must not merge with the scan target path")
	require.Equal(t, "1", generatedURL.Params.Get("request"), "generated URL must include the absolute request target query")
	require.Empty(t, generatedURL.Params.Get("input"), "generated URL must not include the scan target query")

	requestBytes, err := dump(generated, generated.URL(), 0)
	require.NoError(t, err, "could not dump unsafe raw request")
	actualRequestLine := strings.TrimSuffix(strings.SplitN(string(requestBytes.data), "\n", 2)[0], "\r")
	require.Equal(t, requestLine, actualRequestLine, "unsafe raw request line must remain unchanged")
}

func TestMakeRequestFromModelUniqueInteractsh(t *testing.T) {

	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-unique-interactsh"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}/?u=http://{{interactsh-url}}/&href=http://{{interactsh-url}}/&action=http://{{interactsh-url}}/&host={{interactsh-url}}"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)

	generator.options.Interactsh, err = interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.Nil(t, err, "could not create interactsh client")

	inputData, payloads, _ := generator.nextValue()
	got, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), "https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")

	// check if all the interactsh markers are replaced with unique urls
	require.NotContains(t, got.request.String(), "{{interactsh-url}}", "could not get correct interactsh url")
	// check the length of returned urls
	require.Equal(t, len(got.interactshURLs), 4, "could not get correct interactsh url")
	// check if the interactsh urls are unique
	require.True(t, areUnique(got.interactshURLs), "interactsh urls are not unique")
}

func TestMakeSelfContainedRequestRendersPayloadInteractshMarker(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-self-contained-payload-interactsh"
	request := &Request{
		ID:            templateID,
		Name:          "testing",
		SelfContained: true,
		Path:          []string{"http://{{payload}}/callback"},
		Method:        HTTPMethodTypeHolder{MethodType: HTTPGet},
		Payloads: map[string]interface{}{
			"payload": []string{"{{interactsh-url}}"},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.Nil(t, err, "could not create interactsh client")
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	err = request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	got, err := generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), ""), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make self-contained http request")

	require.Len(t, got.interactshURLs, 1)
	require.Equal(t, "http://"+got.interactshURLs[0]+"/callback", got.request.String())
	require.NotContains(t, got.request.String(), "{{interactsh-url}}")
}

func TestMakeSelfContainedRequestPrefersDynamicValueOverTemplateContext(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{
		ID:            "testing-self-contained-dynamic-value",
		Name:          "testing",
		SelfContained: true,
		Path:          []string{"http://example.com/{{token}}"},
		Method:        HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), "")
	executerOpts.GetTemplateCtx(input.MetaInput).Set("token", "stale")
	generator := request.newGenerator(false)
	inputData, payloads, ok := generator.nextValue()
	require.True(t, ok)
	generated, err := generator.Make(context.Background(), input, inputData, payloads, map[string]interface{}{"token": "current"})
	require.NoError(t, err)
	require.Equal(t, "http://example.com/current", generated.request.String())
}

func TestMakeSelfContainedRequestDoesNotAllocateRuntimeInteractshMarkerFromPayload(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-self-contained-runtime-interactsh"
	request := &Request{
		ID:            templateID,
		Name:          "testing",
		SelfContained: true,
		Path:          []string{"http://example.com/callback"},
		Method:        HTTPMethodTypeHolder{MethodType: HTTPPost},
		Body:          "{{payload}}",
		Payloads: map[string]interface{}{
			"payload": []string{"{{server_value}}"},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.Nil(t, err, "could not create interactsh client")
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	err = request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	got, err := generator.Make(
		context.Background(),
		contextargs.NewWithInput(context.Background(), ""),
		inputData,
		payloads,
		map[string]interface{}{
			"server_value": "{{interactsh-url}}",
		},
	)
	require.Nil(t, err, "could not make self-contained http request")
	body, err := got.request.BodyBytes()
	require.Nil(t, err, "could not read request body")

	require.Empty(t, got.interactshURLs)
	require.Equal(t, "{{interactsh-url}}", string(body))
}

func TestSelfContainedRawRequestSendsResponseDataLiterally(t *testing.T) {
	const envName = "NUCLEI_TEST_SELF_CONTAINED_ENV"

	t.Setenv(envName, "ENV-VALUE")

	// A fresh Options pointer, because option payloads are cached per pointer.
	options := testutils.DefaultOptions.Copy()
	options.EnvironmentVariables = true
	testutils.Init(options)

	tests := []struct {
		name string
		body string
	}{
		{name: "template variable", body: "{{secret}}"},
		{name: "helper expression", body: "{{to_upper(seed)}}"},
		{name: "environment variable", body: "{{" + envName + "}}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probes := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/source":
					_, _ = io.WriteString(w, tt.body)
				case "/probe":
					header := r.Header.Clone()
					header.Set("Host", r.Host)

					probes <- header
				}
			}))
			t.Cleanup(server.Close)

			request := &Request{
				ID:            "testing-self-contained-raw-response-data",
				SelfContained: true,
				// Send the probe even though it holds a literal {{...}}.
				SkipVariablesCheck: true,
				Raw: []string{
					"GET " + server.URL + "/source HTTP/1.1\nHost: {{Hostname}}\n\n",
					"GET " + server.URL + "/probe HTTP/1.1\nHost: {{Hostname}}\n" +
						"Probe: [{{tpl}}]\nAuthored: [{{base64(seed)}}-{{" + envName + "}}]\n\n",
				},
				Operators: operators.Operators{
					Extractors: []*extractors.Extractor{{
						Name:     "tpl",
						Part:     "body",
						Type:     extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
						Regex:    []string{".+"},
						Internal: true,
					}},
				},
			}
			templateVars := variables.Variable{
				InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
			}
			templateVars.Set("seed", "hello")
			templateVars.Set("secret", "TOP-SECRET")
			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   request.ID,
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
			})
			executerOpts.Variables = templateVars
			require.NoError(t, request.Compile(executerOpts))

			err := request.ExecuteWithResults(
				contextargs.NewWithInput(context.Background(), ""),
				make(output.InternalEvent),
				make(output.InternalEvent),
				func(*output.InternalWrappedEvent) {},
			)
			require.NoError(t, err)

			var probe http.Header
			select {
			case probe = <-probes:
			default:
				t.Fatal("probe request was not sent")
			}

			require.Equal(t, "["+tt.body+"]", probe.Get("Probe"), "response data must be sent unchanged")
			// Template-authored text still renders, including variables derived
			// from the request URL.
			require.Equal(t, "[aGVsbG8=-ENV-VALUE]", probe.Get("Authored"))
			require.Equal(t, strings.TrimPrefix(server.URL, "http://"), probe.Get("Host"))
		})
	}
}

// makeSelfContainedRawRequest compiles request as a self-contained raw request
// with the given template variables and makes its first request.
func makeSelfContainedRawRequest(t *testing.T, request *Request, vars [][2]string, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	t.Helper()

	options := testutils.DefaultOptions
	testutils.Init(options)

	request.ID = "testing-self-contained-raw"
	request.SelfContained = true
	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(len(vars)),
	}

	for _, v := range vars {
		templateVars.Set(v[0], v[1])
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.Variables = templateVars
	require.NoError(t, request.Compile(executerOpts))

	generator := request.newGenerator(false)
	inputData, payloads, ok := generator.nextValue()
	require.True(t, ok)

	return generator.Make(context.Background(), contextargs.NewWithInput(context.Background(), ""), inputData, payloads, dynamicValues)
}

func TestMakeSelfContainedRawRequestResolvesURLVariables(t *testing.T) {
	request := &Request{
		Raw: []string{"GET http://198.51.100.7/?t={{token}}&d={{data_token}} HTTP/1.1\nHost: {{Hostname}}\n" +
			"X-Var: {{host_var}}\nX-Upper: {{upper_host}}\nX-Payload: {{user}}\n" +
			"X-Token: {{token}}\nX-Data-Token: {{data_token}}\nX-Data: {{data}}\n\n"},
		Payloads: map[string]interface{}{"user": []string{"admin@{{Hostname}}"}},
		// Send values that hold a literal {{...}} from data.
		SkipVariablesCheck: true,
	}
	got, err := makeSelfContainedRawRequest(t, request, [][2]string{
		{"token", "{{rand_base(8)}}"},
		{"data_token", "{{rand_base(8)}}-{{tpl}}"},
		{"data", "{{tpl}}"},
		{"host_var", "{{Hostname}}"},
		{"upper_host", "{{to_upper(host_var)}}"},
	}, map[string]interface{}{"tpl": "{{Hostname}}"})
	require.NoError(t, err)

	require.Equal(t, "198.51.100.7", got.request.Header.Get("X-Var"))
	require.Equal(t, "198.51.100.7", got.request.Header.Get("X-Upper"))
	require.Equal(t, "admin@198.51.100.7", got.request.Header.Get("X-Payload"))
	// Data that names a URL variable is sent unchanged.
	require.Equal(t, "{{Hostname}}", got.request.Header.Get("X-Data"))
	// Values whose template text names no URL variable are not evaluated
	// again, even when data inserted into them does.
	require.Equal(t, got.request.Params.Get("t"), got.request.Header.Get("X-Token"))
	require.Equal(t, got.request.Params.Get("d"), got.request.Header.Get("X-Data-Token"))
	require.True(t, strings.HasSuffix(got.request.Header.Get("X-Data-Token"), "-{{Hostname}}"))
}

func TestMakeSelfContainedRawRequestRejectsMovedRequestLine(t *testing.T) {
	request := &Request{
		Raw: []string{"@timeout: {{wait}}\nGET http://198.51.100.7/ HTTP/1.1\nHost: {{Hostname}}\n\n"},
	}
	_, err := makeSelfContainedRawRequest(t, request, nil, map[string]interface{}{
		"wait": "5s\nGET http://192.0.2.1/secret HTTP/1.1",
	})
	require.ErrorContains(t, err, "changed the request line")
}

func TestSplitRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                           string
		raw                            string
		annotations, requestLine, rest string
		wantErr                        bool
	}{
		{
			name:        "no annotations",
			raw:         "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
			requestLine: "GET http://a/ HTTP/1.1\r",
			rest:        "\nHost: a\r\n\r\n",
		},
		{
			name:        "annotations",
			raw:         "@tls-sni: {{Hostname}}\n@timeout: 5s\nGET http://a/ HTTP/1.1\nHost: a\n",
			annotations: "@tls-sni: {{Hostname}}\n@timeout: 5s\n",
			requestLine: "GET http://a/ HTTP/1.1",
			rest:        "\nHost: a\n",
		},
		{name: "no line break", raw: "GET http://a/ HTTP/1.1", wantErr: true},
		{name: "annotations only", raw: "@timeout: 5s\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			annotations, requestLine, rest, err := splitRequestLine(tt.raw)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.annotations, annotations)
			require.Equal(t, tt.requestLine, requestLine)
			require.Equal(t, tt.rest, rest)
		})
	}
}

func TestExecuteRequestDoesNotReevaluateGeneratedPayloadMetadata(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http-payload-metadata-data"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{server.URL},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator(false)
	inputData, payloads, _ := generator.nextValue()
	input := contextargs.NewWithInput(context.Background(), server.URL)
	generated, err := generator.Make(context.Background(), input, inputData, payloads, map[string]interface{}{
		"secret": "leaked-secret",
	})
	require.Nil(t, err, "could not make http request")
	generated.meta = map[string]interface{}{
		"payload": "{{secret}}",
	}

	err = request.executeRequest(input, generated, nil, false, func(*output.InternalWrappedEvent) {}, 0)

	require.Nil(t, err, "could not execute http request")
	require.Equal(t, "{{secret}}", generated.meta["payload"])
}

// areUnique checks if the elements of string slice are unique
func areUnique(elements []string) bool {
	encountered := map[string]bool{}
	for v := range elements {
		if encountered[elements[v]] {
			return false
		}
		encountered[elements[v]] = true
	}
	return true
}
