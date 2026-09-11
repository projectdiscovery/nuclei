package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// chatCompletionsStub serves a canned /v1/chat/completions response.
func chatCompletionsStub(t *testing.T, body string) *openAIResolver {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return newOpenAIResolver(server.URL+"/v1", "test-model", "", 10*time.Second)
}

// A reasoning model can spend its whole output allowance before emitting any
// content. That used to surface as "fragment is empty", which points at the
// wrong thing entirely.
func TestOpenAIResolverReportsTruncationRatherThanEmptyContent(t *testing.T) {
	resolver := chatCompletionsStub(t, `{
		"choices": [{"index": 0, "finish_reason": "length", "message": {"role": "assistant", "content": ""}}],
		"usage": {"completion_tokens": 4096}
	}`)

	_, err := resolver.Resolve(context.Background(), "find exposed admin panels", "")
	require.ErrorContains(t, err, "truncated the response after 4096 tokens")
}

func TestOpenAIResolverReturnsFragment(t *testing.T) {
	resolver := chatCompletionsStub(t, `{
		"choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/admin\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"}}]
	}`)

	fragment, err := resolver.Resolve(context.Background(), "find exposed admin panels", "")
	require.NoError(t, err)
	require.NoError(t, validateFragment(fragment))
}

func TestOpenAIResolverRejectsEmptyChoices(t *testing.T) {
	resolver := chatCompletionsStub(t, `{"choices": []}`)

	_, err := resolver.Resolve(context.Background(), "find exposed admin panels", "")
	require.ErrorContains(t, err, "no choices")
}
