package runner

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	utilsllm "github.com/projectdiscovery/utils/llm"
)

// llmMatcherClient adapts the shared provider layer to the minimal interface
// the matchers package needs, keeping matchers free of any provider SDK import.
type llmMatcherClient struct {
	client *utilsllm.Client
	model  string
}

// Model names the model behind a verdict so it can be recorded in the finding.
func (a *llmMatcherClient) Model() string {
	return a.model
}

func (a *llmMatcherClient) Complete(ctx context.Context, prompt string, asJSON bool) (string, error) {
	return a.client.Complete(ctx, utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
}

// llmJudgeClient is an llmMatcherClient whose provider classifies natively, so
// llm matchers ask it through Judge instead of Complete.
type llmJudgeClient struct {
	*llmMatcherClient
	warnComplete sync.Once
}

func (a *llmJudgeClient) Judge(ctx context.Context, question string, labels, inputs []string) (llmclient.Verdict, error) {
	verdict, err := a.client.Judge(ctx, utilsllm.JudgeRequest{Question: question, Labels: labels, Inputs: inputs})
	if err != nil {
		return llmclient.Verdict{}, err
	}
	return llmclient.Verdict{Label: verdict.Label, Confidence: verdict.Confidence, Model: verdict.Model}, nil
}

// Complete is only reached by llm extractors, which need free text a
// classifier cannot produce. Returning here spends no call budget and
// makes no provider request. Extractors turn the error into an empty
// result, and the warning says why.
func (a *llmJudgeClient) Complete(context.Context, string, bool) (string, error) {
	a.warnComplete.Do(func() {
		gologger.Warning().Msgf("llm provider %q cannot run llm extractors, they return nothing", utilsllm.ProviderJev)
	})
	return "", errors.New("llm provider cannot run extractors")
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

	matcherClient := &llmMatcherClient{client: client, model: options.LLMModel}
	if client.CanJudge() {
		return &llmJudgeClient{llmMatcherClient: matcherClient}, nil
	}
	return matcherClient, nil
}
