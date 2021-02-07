package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestHTTPCompile(t *testing.T) {
	options := testutils.DefaultOptions
	options.CustomHeaders = []string{"User-Agent: test", "Hello: World"}

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
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")
	require.Equal(t, 6, request.Requests(), "could not get correct number of requests")
	require.Equal(t, map[string]string{"User-Agent": "test", "Hello": "World"}, request.customHeaders, "could not get correct custom headers")
}
