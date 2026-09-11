package ai

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
)

// apiKeyEnv is the only place a key is read from. Keys are deliberately not
// exposed as a flag so they cannot leak through shell history or process args.
const apiKeyEnv = "NUCLEI_AI_API_KEY"

// defaultProvider is used when neither a provider nor a base url is given.
const defaultProvider = "openai"

// providerPresets are base urls for well known /v1/chat/completions endpoints.
//
// Any other provider works through -ai-base-url, including self-hosted
// gateways, which is why this table stays short rather than trying to be a
// registry of every vendor.
var providerPresets = map[string]string{
	"openai":     "https://api.openai.com/v1",
	"groq":       "https://api.groq.com/openai/v1",
	"openrouter": "https://openrouter.ai/api/v1",
	"together":   "https://api.together.xyz/v1",
	"ollama":     "http://localhost:11434/v1",
	"llamacpp":   "http://localhost:8080/v1",
	"lmstudio":   "http://localhost:1234/v1",
	"vllm":       "http://localhost:8000/v1",
}

// ProviderNames returns the known provider presets, sorted so help output is
// stable across runs.
func ProviderNames() []string {
	names := make([]string, 0, len(providerPresets))
	for name := range providerPresets {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// ProviderConfig selects the model that expands prompts.
type ProviderConfig struct {
	// Provider names a preset in providerPresets. Ignored when BaseURL is set.
	Provider string
	// BaseURL points at any OpenAI compatible /v1 endpoint.
	BaseURL string
	// Model is the model identifier passed through to the provider.
	Model string
	// Timeout bounds a single expansion call.
	Timeout time.Duration
}

// openAICompatibleResolver talks to any /v1/chat/completions endpoint.
//
// That one wire format covers every local runtime (ollama, llama.cpp, vLLM,
// LM Studio) alongside the hosted providers, so offline use is the same code
// path as frontier use rather than a bolted-on special case.
type openAICompatibleResolver struct {
	baseURL string
	model   string
	apiKey  string
	client  *http.Client
}

// NewResolver builds a resolver from provider configuration.
func NewResolver(config ProviderConfig) (Resolver, error) {
	baseURL := strings.TrimSuffix(config.BaseURL, "/")
	if baseURL == "" {
		// the default lives here rather than only in the flag definition so
		// that SDK callers who set just a model behave like the CLI
		provider := strings.ToLower(config.Provider)
		if provider == "" {
			provider = defaultProvider
		}

		preset, ok := providerPresets[provider]
		if !ok {
			return nil, errkit.Newf("unknown ai provider %q, set a base url for a custom endpoint", config.Provider)
		}
		baseURL = preset
	}

	if config.Model == "" {
		return nil, errkit.New("no ai model configured, set -ai-model")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	return &openAICompatibleResolver{
		baseURL: baseURL,
		model:   config.Model,
		apiKey:  os.Getenv(apiKeyEnv),
		client:  &http.Client{Timeout: timeout},
	}, nil
}

// Resolve maps a prompt onto nuclei protocol primitives.
func (resolver *openAICompatibleResolver) Resolve(ctx context.Context, prompt string, model string) ([]byte, error) {
	if model == "" {
		model = resolver.model
	}

	fragment, err := resolver.complete(ctx, model, capabilityContract, prompt)
	if err != nil {
		return nil, err
	}

	// One corrective round trip, which matters most for smaller local models:
	// they get the intent right far more often than they get the shape right.
	if parseErr := validateFragment(fragment); parseErr != nil {
		retry := fmt.Sprintf("%s\n\nYour previous answer was rejected: %s\nReturn only the corrected YAML.", prompt, parseErr)
		if fragment, err = resolver.complete(ctx, model, capabilityContract, retry); err != nil {
			return nil, err
		}
		if parseErr = validateFragment(fragment); parseErr != nil {
			return nil, errkit.Wrap(parseErr, "resolver did not return a usable fragment")
		}
	}

	return fragment, nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (resolver *openAICompatibleResolver) complete(ctx context.Context, model, system, user string) ([]byte, error) {
	// temperature 0 so that a cache miss on the same prompt tends to produce
	// the same fragment, which keeps template review meaningful
	body, err := json.Marshal(chatRequest{
		Model:       model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return nil, errkit.Wrap(err, "could not encode resolver request")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, errkit.Wrap(err, "could not build resolver request")
	}

	request.Header.Set("Content-Type", "application/json")
	if resolver.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+resolver.apiKey)
	}

	response, err := resolver.client.Do(request)
	if err != nil {
		return nil, errkit.Wrap(err, "could not reach ai provider")
	}

	defer func() {
		_ = response.Body.Close()
	}()

	var decoded chatResponse
	if err = json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, errkit.Wrapf(err, "could not decode ai provider response (status %d)", response.StatusCode)
	}

	if decoded.Error != nil {
		return nil, errkit.Newf("ai provider error: %s", decoded.Error.Message)
	}

	if len(decoded.Choices) == 0 {
		return nil, errkit.Newf("ai provider returned no choices (status %d)", response.StatusCode)
	}

	return []byte(stripCodeFence(decoded.Choices[0].Message.Content)), nil
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
