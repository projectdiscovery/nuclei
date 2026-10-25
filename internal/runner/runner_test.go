package runner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestCreateReportingOptions(t *testing.T) {
	var options types.Options
	options.ReportingConfig = filepath.Join("testdata", "test-issue-tracker-config1.yaml")
	resultOptions, err := createReportingOptions(&options)

	require.Nil(t, err)
	require.Equal(t, resultOptions.AllowList.Severities, severity.Severities{severity.High, severity.Critical})
	require.Equal(t, resultOptions.DenyList.Severities, severity.Severities{severity.Low})

	options.ReportingConfig = filepath.Join("testdata", "test-issue-tracker-config2.yaml")
	resultOptions2, err := createReportingOptions(&options)
	require.Nil(t, err)
	require.Equal(t, resultOptions2.AllowList.Severities, resultOptions.AllowList.Severities)
	require.Equal(t, resultOptions2.DenyList.Severities, resultOptions.DenyList.Severities)
}

type TestStruct1 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct2 `yaml:"b"`
}

type TestStruct2 struct {
	B string `yaml:"b"`
}

type TestStruct3 struct {
	A string `yaml:"a"`
	B string `yaml:"b"`
	C string `yaml:"c"`
}

type TestStruct4 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct3 `yaml:"b"`
}

type TestStruct5 struct {
	A []string  `yaml:"a"`
	B [2]string `yaml:"b"`
}

type TestStruct6 struct {
	A string       `yaml:"a"`
	B *TestStruct2 `yaml:"b"`
	C string
}

func TestWalkReflectStructAssignsEnvVars(t *testing.T) {
	testStruct := &TestStruct1{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct2{
			B: "$VAR_TWO",
		},
	}
	_ = os.Setenv("VAR_EXAMPLE", "value")
	_ = os.Setenv("VAR_TWO", "value2")

	Walk(testStruct, expandEndVars)

	require.Equal(t, "value", testStruct.A)
	require.Equal(t, "value2", testStruct.Struct.B)
}

func TestWalkReflectStructHandlesDifferentTypes(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "$VAR_TWO",
		C: "$VAR_THREE",
	}
	_ = os.Setenv("VAR_EXAMPLE", "value")
	_ = os.Setenv("VAR_TWO", "2")
	_ = os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	require.Equal(t, "value", testStruct.A)
	require.Equal(t, "2", testStruct.B)
	require.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructEmpty(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "",
		C: "$VAR_THREE",
	}
	_ = os.Setenv("VAR_EXAMPLE", "value")
	_ = os.Setenv("VAR_TWO", "2")
	_ = os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	require.Equal(t, "value", testStruct.A)
	require.Equal(t, "", testStruct.B)
	require.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructWithNoYamlTag(t *testing.T) {
	test := &TestStruct6{
		A: "$GITHUB_USER",
		B: &TestStruct2{
			B: "$GITHUB_USER",
		},
		C: "$GITHUB_USER",
	}

	_ = os.Setenv("GITHUB_USER", "testuser")

	Walk(test, expandEndVars)
	require.Equal(t, "testuser", test.A)
	require.Equal(t, "testuser", test.B.B, test.B)
	require.Equal(t, "$GITHUB_USER", test.C)
}

func TestWalkReflectStructHandlesNestedStructs(t *testing.T) {
	testStruct := &TestStruct4{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct3{
			B: "$VAR_TWO",
			C: "$VAR_THREE",
		},
	}
	_ = os.Setenv("VAR_EXAMPLE", "value")
	_ = os.Setenv("VAR_TWO", "2")
	_ = os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	require.Equal(t, "value", testStruct.A)
	require.Equal(t, "2", testStruct.Struct.B)
	require.Equal(t, "true", testStruct.Struct.C)
}

func TestNewInteractshHTTPClient(t *testing.T) {
	// ProxyFromEnvironment reads the environment once per process. Set it
	// before the first request. NO_PROXY keeps the local dial direct.
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "https_proxy", "no_proxy"} {
		t.Setenv(key, "")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	options := &types.Options{
		ExecutionId: "test-interactsh-client-dialer",
		Timeout:     35,
	}
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	client := newInteractshHTTPClient(options)
	require.NotNil(t, client)
	require.Equal(t, 35*time.Second, client.HTTPClient.Timeout)

	transport, ok := client.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.Proxy)
	require.NotNil(t, transport.DialContext)
	require.NotNil(t, transport.DialTLSContext)
	require.NotNil(t, transport.TLSClientConfig, "INTERACTSH_TLS_VERIFY edits this config")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	resp, err := client.HTTPClient.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	host := srv.Listener.Addr().(*net.TCPAddr).IP.String()
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	require.Equal(t, host, dialers.Fastdialer.GetDialedIP(host))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	proxyURL, err := transport.Proxy(req)
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	require.Equal(t, "http://127.0.0.1:9", proxyURL.String())
}
