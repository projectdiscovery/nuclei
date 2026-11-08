package http

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/retryablehttp-go"
)

func newCustomHeaderTestRequest(t *testing.T, headers map[string]string) *Request {
	t.Helper()

	options := testutils.DefaultOptions
	testutils.Init(options)

	return &Request{
		customHeaders: headers,
		options: testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "testing-custom-header-dsl",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		}),
	}
}

func generateCustomHeader(t *testing.T, request *Request, header string) string {
	t.Helper()

	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	require.Nil(t, err, "could not create request")

	request.setCustomHeaders(&generatedRequest{request: req})

	return req.Header.Get(header)
}

// TestCustomHeaderDSLEvaluatedPerRequest is the whole point of the feature: a
// -H value carrying rand_user_agent() must resolve again on every generated
// request, so the UA keeps rotating while the operator's tag stays attached.
func TestCustomHeaderDSLEvaluatedPerRequest(t *testing.T) {
	request := newCustomHeaderTestRequest(t, map[string]string{
		"User-Agent": "{{rand_user_agent()}} myprop/value",
	})

	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		value := generateCustomHeader(t, request, "User-Agent")
		require.Contains(t, value, "myprop/value", "tag was dropped from the user agent")
		require.NotEqual(t, "{{rand_user_agent()}} myprop/value", value, "expression was not evaluated")
		seen[value] = struct{}{}
	}

	require.Greater(t, len(seen), 1, "user agent was frozen instead of evaluated per request")
}

func TestCustomHeaderWithoutExpressionIsUnchanged(t *testing.T) {
	request := newCustomHeaderTestRequest(t, map[string]string{
		"User-Agent": "myprop/value",
		"X-Scan-Id":  "abc",
	})

	require.Equal(t, "myprop/value", generateCustomHeader(t, request, "User-Agent"))
	require.Equal(t, "abc", generateCustomHeader(t, request, "X-Scan-Id"))
}

// TestUnsafeRawCustomHeaderIsEvaluated covers the unsafe raw path, which splices
// the -H line into UnsafeRawBytes via TryFillCustomHeaders and so never takes
// the header from setCustomHeaders. It drives real request generation and reads
// the resulting wire bytes, otherwise it would not guard that wiring.
func TestUnsafeRawCustomHeaderIsEvaluated(t *testing.T) {
	options := testutils.DefaultOptions
	options.CustomHeaders = []string{"User-Agent: {{rand_user_agent()}} myprop/value"}
	testutils.Init(options)

	templateID := "testing-unsafe-raw-header"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Unsafe: true,
		Raw:    []string{"GET /unsafe HTTP/1.1\nHost: {{Hostname}}\n\n"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.Nil(t, request.Compile(executerOpts), "could not compile http request")

	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		generator := request.newGenerator(false)
		inputData, payloads, ok := generator.nextValue()
		require.True(t, ok, "could not get next value from generator")

		req, err := generator.Make(context.Background(),
			contextargs.NewWithInput(context.Background(), "https://example.com"),
			inputData, payloads, map[string]interface{}{})
		require.Nil(t, err, "could not make http request")
		require.NotNil(t, req.rawRequest, "expected an unsafe raw request")

		wire := string(req.rawRequest.UnsafeRawBytes)
		require.NotContains(t, wire, marker.ParenthesisOpen+"rand_user_agent", "expression reached the wire unevaluated")
		require.Contains(t, wire, "myprop/value", "tag was dropped from the wire bytes")

		userAgent, found := rawUserAgentLine(wire)
		require.True(t, found, "no User-Agent header in the wire bytes")
		seen[userAgent] = struct{}{}
	}

	require.Greater(t, len(seen), 1, "user agent was frozen instead of evaluated per request")
}

func rawUserAgentLine(wire string) (string, bool) {
	for _, line := range strings.Split(wire, "\r\n") {
		if after, ok := strings.CutPrefix(line, "User-Agent: "); ok {
			return after, true
		}
	}
	return "", false
}

// TestCustomHeaderWithBrokenExpressionKeepsOriginal keeps a typo in -H from
// killing the scan: the raw value goes out and the error is only logged.
func TestCustomHeaderWithBrokenExpressionKeepsOriginal(t *testing.T) {
	request := newCustomHeaderTestRequest(t, map[string]string{
		"User-Agent": "{{no_such_helper()}} myprop",
	})

	require.Equal(t, "{{no_such_helper()}} myprop", generateCustomHeader(t, request, "User-Agent"))
}
