package runner

import (
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
