package http

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
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

// TestUnsafeRawCustomHeaderIsEvaluated covers the unsafe raw path, which
// splices the -H line into the request bytes via TryFillCustomHeaders and so
// never reaches setCustomHeaders. Without this the literal {{...}} marker would
// go out on the wire.
func TestUnsafeRawCustomHeaderIsEvaluated(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		value := evaluateCustomHeaderExpressions("testing-unsafe-raw",
			"User-Agent: {{rand_user_agent()}} myprop/value", map[string]interface{}{})
		require.True(t, strings.HasPrefix(value, "User-Agent: "), "header name was mangled")
		require.NotContains(t, value, marker.ParenthesisOpen, "expression was left unevaluated")
		require.Contains(t, value, "myprop/value", "tag was dropped")
		seen[value] = struct{}{}
	}

	require.Greater(t, len(seen), 1, "user agent was frozen instead of evaluated per request")
}

// TestCustomHeaderWithBrokenExpressionKeepsOriginal keeps a typo in -H from
// killing the scan: the raw value goes out and the error is only logged.
func TestCustomHeaderWithBrokenExpressionKeepsOriginal(t *testing.T) {
	request := newCustomHeaderTestRequest(t, map[string]string{
		"User-Agent": "{{no_such_helper()}} myprop",
	})

	require.Equal(t, "{{no_such_helper()}} myprop", generateCustomHeader(t, request, "User-Agent"))
}
