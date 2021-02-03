package http

import (
	"fmt"
	"net/http/httputil"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/stretchr/testify/require"
)

func TestMakeRequestFromModal(t *testing.T) {

}

func TestMakeRequestFromRaw(t *testing.T) {
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
Authorization: Basic {{base64(username + ':' + password)}}
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0
Accept-Language: en-US,en;q=0.9
Connection: close`},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http request")

	generator := request.newGenerator()
	req, err := generator.Make("https://example.com", map[string]interface{}{})
	require.Nil(t, err, "could not make http request")

	data, _ := httputil.DumpRequest(req.request.Request, true)
	fmt.Printf("%s: %+v\n", string(data), req)
}

func TestGetPayloadValues(t *testing.T) {
	req := &Request{
		Payloads: map[string]interface{}{
			"username": []string{"test", "admin", "pass"},
		},
	}
	var err error
	req.generator, err = generators.New(req.Payloads, generators.Sniper, "")
	require.Nil(t, err, "could not create generators")

	generator := req.newGenerator()
	_ = generator
	//values, err := generator.getPayloadValues("https://example.com", map[string]interface{}{
	//	"username": "{{base64('username')}}",
	//})
	//fmt.Printf("%+v %+v\n", values, err)
}
