package runner

import (
	"time"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	orcallm "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm/orca"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// configureLLM builds the scan's llm client from options. It returns nil unless
// -llm is set, so nothing reaches a model until the user opts in.
//
// Credential resolution lives in the provider layer, not here: OrcaRouter's
// credential comes from the shared seam (an explicit key, an environment
// variable, or the key a PKCE login stored), and every other provider keeps the
// existing environment-only behaviour. The key is never read into options, so it
// cannot reach a log or a resume file.
//
// The client is returned rather than installed globally so two scans in one
// process cannot overwrite each other's provider, cache, budget, or timeout.
func configureLLM(options *types.Options) (llmclient.Client, error) {
	if !options.EnableLLM {
		return nil, nil
	}

	return orcallm.New(orcallm.Config{
		Provider:       options.LLMProvider,
		BaseURL:        options.LLMBaseURL,
		Model:          options.LLMModel,
		APIKey:         options.LLMAPIKey,
		AuthBaseURL:    options.LLMAuthBaseURL,
		APIBaseURL:     options.LLMAPIBaseURL,
		Timeout:        time.Duration(options.LLMTimeout) * time.Second,
		Cache:          options.LLMCache,
		MaxCalls:       options.LLMMaxCalls,
		MaxConcurrency: options.LLMConcurrency,
	})
}
