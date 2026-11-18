package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestConfigureLLMExposesJudgeOnlyForClassifiers(t *testing.T) {
	t.Setenv("LLM_API_KEY", "key")

	client, err := configureLLM(&types.Options{EnableLLM: true, LLMProvider: "jev", LLMModel: "jev-latest"})
	require.NoError(t, err)
	require.Implements(t, (*llmclient.Judge)(nil), client)

	client, err = configureLLM(&types.Options{EnableLLM: true, LLMProvider: "ollama", LLMModel: "llama3.2"})
	require.NoError(t, err)
	_, isJudge := client.(llmclient.Judge)
	require.False(t, isJudge, "chat providers keep the Complete path")
}

func TestJevExtractorDoesNotSpendCallBudget(t *testing.T) {
	t.Setenv("LLM_API_KEY", "key")
	// ProxyFromEnvironment caches the first request in the process. Match the
	// proxy the interactsh client test expects, and keep the local server direct.
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "https_proxy", "no_proxy"} {
		t.Setenv(key, "")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"model":"jev-1.14.0","answers":{"q":{"type":"noul","noul":0.9}}}`))
	}))
	t.Cleanup(server.Close)

	client, err := configureLLM(&types.Options{
		EnableLLM:   true,
		LLMProvider: "jev",
		LLMBaseURL:  server.URL + "/v1",
		LLMModel:    "jev-latest",
		LLMMaxCalls: 1,
	})
	require.NoError(t, err)

	_, err = client.Complete(context.Background(), "extract the title", true)
	require.ErrorContains(t, err, "cannot run extractors")
	_, err = client.Complete(context.Background(), "extract another", true)
	require.Error(t, err)
	require.Zero(t, calls.Load())

	judge := client.(llmclient.Judge)
	verdict, err := judge.Judge(context.Background(), "login page?", nil, []string{"<form>"})
	require.NoError(t, err)
	require.Equal(t, "yes", verdict.Label)
	require.EqualValues(t, 1, calls.Load())
}
