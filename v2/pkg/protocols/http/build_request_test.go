package http

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

func TestBaseURLWithTemplatePrefs(t *testing.T) {
	baseURL := "http://localhost:53/test"
	parsed, _ := url.Parse(baseURL)

	data := "{{BaseURL}}:8000/newpath"
	data, parsed = baseURLWithTemplatePrefs(data, parsed)
	require.Equal(t, "http://localhost:8000/test", parsed.String(), "could not get correct value")
	require.Equal(t, "{{BaseURL}}/newpath", data, "could not get correct data")
}

func TestVariables(t *testing.T) {
	baseURL := "http://localhost:9001/test/123"
	parsed, _ := url.Parse(baseURL)
	values := generateVariables(parsed, true)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["RootURL"], "http://localhost:9001", "incorrect rootURL")
	require.Equal(t, values["Host"], "localhost", "incorrect domain name")
	require.Equal(t, values["Path"], "/test", "incorrect path")
	require.Equal(t, values["File"], "123", "incorrect file")
	require.Equal(t, values["Port"], "9001", "incorrect port number")
	require.Equal(t, values["Scheme"], "http", "incorrect scheme")
	require.Equal(t, values["Hostname"], "localhost:9001", "incorrect hostname")

	baseURL = "https://example.com"
	parsed, _ = url.Parse(baseURL)
	values = generateVariables(parsed, false)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "example.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "https://example.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "443", "incorrect port number")
	require.Equal(t, values["Scheme"], "https", "incorrect scheme")
	require.Equal(t, values["Hostname"], "example.com", "incorrect hostname")

	baseURL = "ftp://foobar.com/"
	parsed, _ = url.Parse(baseURL)
	values = generateVariables(parsed, true)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "foobar.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "ftp://foobar.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "", "incorrect port number") // Unsupported protocol results in a blank port
	require.Equal(t, values["Scheme"], "ftp", "incorrect scheme")
	require.Equal(t, values["Hostname"], "foobar.com", "incorrect hostname")
}

func TestMakeRequestFromModal(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}/login.php"},
		Method: "POST",
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

	generator := request.newGenerator()
	req, err := generator.Make("https://example.com", map[string]interface{}{}, "")
	require.Nil(t, err, "could not make http request")

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
		Method: "GET",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator()
	req, err := generator.Make("https://example.com/test.php", map[string]interface{}{}, "")
	require.Nil(t, err, "could not make http request")
	require.Equal(t, "https://example.com/test.php?query=example", req.request.URL.String(), "could not get correct request path")

	generator = request.newGenerator()
	req, err = generator.Make("https://example.com/test/", map[string]interface{}{}, "")
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
		AttackType: "clusterbomb",
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

	generator := request.newGenerator()
	req, err := generator.Make("https://example.com", map[string]interface{}{}, "")
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic admin:admin", authorization, "could not get correct authorization headers from raw")

	req, err = generator.Make("https://example.com", map[string]interface{}{}, "")
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
		AttackType: "clusterbomb",
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

	generator := request.newGenerator()
	req, err := generator.Make("https://example.com", map[string]interface{}{}, "")
	require.Nil(t, err, "could not make http request")
	authorization := req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46YWRtaW4=", authorization, "could not get correct authorization headers from raw")

	req, err = generator.Make("https://example.com", map[string]interface{}{}, "")
	require.Nil(t, err, "could not make http request")
	authorization = req.request.Header.Get("Authorization")
	require.Equal(t, "Basic YWRtaW46Z3Vlc3Q=", authorization, "could not get correct authorization headers from raw")
}
