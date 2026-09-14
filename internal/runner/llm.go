package runner

import (
	"context"
	"time"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	utilsllm "github.com/projectdiscovery/utils/llm"
)

// llmMatcherClient adapts the shared provider layer to the minimal interface
// the matchers package needs, keeping matchers free of any provider SDK import.
type llmMatcherClient struct {
	client *utilsllm.Client
}

func (a *llmMatcherClient) Complete(ctx context.Context, prompt string, asJSON bool) (string, error) {
	return a.client.Complete(ctx, utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
}

// configureLLM builds the scan's llm client from options. It returns nil unless
// -llm is set, so nothing reaches a model until the user opts in. The API key is
// read from the environment by the provider layer, never from options.
//
// The client is returned rather than installed globally so two scans in one
// process cannot overwrite each other's provider, cache, budget, or timeout.
func configureLLM(options *types.Options) (llmclient.Client, error) {
	if !options.EnableLLM {
		return nil, nil
	}

	client, err := utilsllm.New(utilsllm.Config{
		Provider:       options.LLMProvider,
		BaseURL:        options.LLMBaseURL,
		Model:          options.LLMModel,
		Timeout:        time.Duration(options.LLMTimeout) * time.Second,
		Cache:          options.LLMCache,
		MaxCalls:       options.LLMMaxCalls,
		MaxConcurrency: options.LLMConcurrency,
	})
	if err != nil {
		return nil, err
	}

	return &llmMatcherClient{client: client}, nil
}
