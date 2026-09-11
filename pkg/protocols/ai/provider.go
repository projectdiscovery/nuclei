package ai

import (
	"os"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// apiKeyEnv is the only place a key is read from. Keys are deliberately not
// exposed as a flag so they cannot leak through shell history or process args.
const apiKeyEnv = "NUCLEI_AI_API_KEY"

// defaultProvider is used when neither a provider nor a base url is given.
const defaultProvider = "openai"

// providerAnthropic speaks the Messages API rather than chat completions, so it
// is dispatched to its own client instead of carrying a base url preset.
const providerAnthropic = "anthropic"

// maxResponseTokens caps a resolved fragment. Expansions are a handful of
// requests and matchers; anything longer is a runaway answer, not a template.
const maxResponseTokens = 4096

// openAICompatiblePresets are base urls for well known /v1/chat/completions
// endpoints.
//
// Any other OpenAI compatible provider works through a base url, including
// self-hosted gateways, which is why this table stays short rather than trying
// to be a registry of every vendor.
var openAICompatiblePresets = map[string]string{
	"openai":     "https://api.openai.com/v1",
	"groq":       "https://api.groq.com/openai/v1",
	"openrouter": "https://openrouter.ai/api/v1",
	"together":   "https://api.together.xyz/v1",
	"ollama":     "http://localhost:11434/v1",
	"llamacpp":   "http://localhost:8080/v1",
	"lmstudio":   "http://localhost:1234/v1",
	"vllm":       "http://localhost:8000/v1",
}

// ProviderNames returns the known providers, sorted so help output is stable
// across runs.
func ProviderNames() []string {
	names := make([]string, 0, len(openAICompatiblePresets)+1)
	for name := range openAICompatiblePresets {
		names = append(names, name)
	}
	names = append(names, providerAnthropic)

	sort.Strings(names)

	return names
}

// ProviderConfig selects the model that expands prompts.
type ProviderConfig struct {
	// Provider names a known provider. Ignored when BaseURL is set.
	Provider string
	// BaseURL points at any OpenAI compatible /v1 endpoint.
	BaseURL string
	// Model is the model identifier passed through to the provider.
	Model string
	// Timeout bounds a single expansion call.
	Timeout time.Duration
}

// NewResolver builds a resolver from provider configuration.
//
// Anthropic gets its own client because the Messages API is a different wire
// format, not a different host: system prompts are a top-level field, auth is
// x-api-key, and sampling parameters are rejected outright on current models.
func NewResolver(config ProviderConfig) (Resolver, error) {
	if config.Model == "" {
		return nil, errkit.New("no ai model configured, set -ai-model")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	apiKey := os.Getenv(apiKeyEnv)
	provider := strings.ToLower(config.Provider)

	if config.BaseURL == "" && provider == providerAnthropic {
		return newAnthropicResolver(config.Model, apiKey, timeout), nil
	}

	baseURL := strings.TrimSuffix(config.BaseURL, "/")
	if baseURL == "" {
		// the default lives here rather than only in the flag definition so
		// that SDK callers who set just a model behave like the CLI
		if provider == "" {
			provider = defaultProvider
		}

		preset, ok := openAICompatiblePresets[provider]
		if !ok {
			return nil, errkit.Newf("unknown ai provider %q, set a base url for a custom endpoint", config.Provider)
		}
		baseURL = preset
	}

	return newOpenAIResolver(baseURL, config.Model, apiKey, timeout), nil
}

// stripCodeFence removes markdown fencing that models add even when told not
// to. Cheaper to tolerate here than to spend a retry on.
func stripCodeFence(content string) string {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "```") {
		return trimmed
	}

	if index := strings.Index(trimmed, "\n"); index != -1 {
		trimmed = trimmed[index+1:]
	}

	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(trimmed), "```"))
}

// retryPrompt asks a model to correct a fragment that failed validation.
//
// One corrective round trip matters most for smaller local models: they get the
// intent right far more often than they get the shape right.
func retryPrompt(prompt string, cause error) string {
	return prompt + "\n\nYour previous answer was rejected: " + cause.Error() + "\nReturn only the corrected YAML."
}
