package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
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
	req, err := generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	if req.request.URL == nil {
		t.Fatalf("url is nil in generator make")
	}
	bodyBytes, _ := req.request.BodyBytes()
	require.Equal(t, "/login.php", req.request.URL.Path, "could not get correct request path")
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
	req, err := generator.Make(context.Background(), contextargs.NewWithInput("https://example.com/test.php"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	require.Equal(t, "https://example.com/test.php?query=example", req.request.URL.String(), "could not get correct request path")

	generator = request.newGenerator(false)
	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput("https://example.com/test/"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	require.Equal(t, "https://example.com/test/?query=example", req.request.URL.String(), "could not get correct request path")
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
	req, err := generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic admin:admin", authorization, "could not get correct authorization headers from raw")

	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization = req.request.Header.Get("Authorization")
	require.Equal(t, "Basic admin:guest", authorization, "could not get correct authorization headers from raw")
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
	req, err := generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46YWRtaW4=", authorization, "could not get correct authorization headers from raw")

	inputData, payloads, _ = generator.nextValue()
	req, err = generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")
	authorization = req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46Z3Vlc3Q=", authorization, "could not get correct authorization headers from raw")
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
	got, err := generator.Make(context.Background(), contextargs.NewWithInput("https://example.com"), inputData, payloads, map[string]interface{}{})
	require.Nil(t, err, "could not make http request")

	// check if all the interactsh markers are replaced with unique urls
	require.NotContains(t, got.request.URL.String(), "{{interactsh-url}}", "could not get correct interactsh url")
	// check the length of returned urls
	require.Equal(t, len(got.interactshURLs), 4, "could not get correct interactsh url")
	// check if the interactsh urls are unique
	require.True(t, areUnique(got.interactshURLs), "interactsh urls are not unique")
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
