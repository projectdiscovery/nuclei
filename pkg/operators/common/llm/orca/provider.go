package orca

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/projectdiscovery/utils/errkit"
	utilsllm "github.com/projectdiscovery/utils/llm"
)

// ProviderName is the preset id for OrcaRouter.
const ProviderName = "orcarouter"

// ProviderLabel is the human-readable provider name.
const ProviderLabel = "OrcaRouter"

// DefaultModel is the model selected when the user names a provider but no
// model. orcarouter/auto lets the gateway route, so a first run works before
// the user has looked at the catalog.
const DefaultModel = "orcarouter/auto"

// Provider describes one selectable llm provider.
type Provider struct {
	// Name is the preset id accepted by -llm-provider.
	Name string
	// Label is the display name.
	Label string
	// BaseURL is the OpenAI-compatible endpoint, empty when the preset is the
	// generic openai-compatible one that requires an explicit url.
	BaseURL string
	// Hosted reports whether the endpoint needs a credential.
	Hosted bool
	// Local reports whether the endpoint is expected on the local machine.
	Local bool
	// DefaultModel is used when the user selects the provider without a model.
	DefaultModel string
	// Catalog is the model-discovery path, empty when the provider has none.
	Catalog string
}

// OrcaRouter is the first-class OrcaRouter provider entry. It carries the
// inference base URL and the discovery path, which is what makes it a named
// provider rather than a custom endpoint.
func OrcaRouter() Provider {
	return Provider{
		Name:         ProviderName,
		Label:        ProviderLabel,
		BaseURL:      DefaultAPIBaseURL,
		Hosted:       true,
		DefaultModel: DefaultModel,
		Catalog:      ModelsPath + "?capability=" + string(CapabilityChat),
	}
}

// providerRegistry mirrors the presets the shared utils client understands and
// adds OrcaRouter. Keeping the mirror here means the CLI can offer a complete,
// consistent provider list even though the shared table is in another module.
var providerRegistry = map[string]Provider{
	ProviderName: {Name: ProviderName, Label: ProviderLabel, BaseURL: DefaultAPIBaseURL, Hosted: true, DefaultModel: DefaultModel, Catalog: ModelsPath + "?capability=" + string(CapabilityChat)},
	"openai":     {Name: "openai", Label: "OpenAI", BaseURL: "https://api.openai.com/v1", Hosted: true},
	"openrouter": {Name: "openrouter", Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", Hosted: true},
	"groq":       {Name: "groq", Label: "Groq", BaseURL: "https://api.groq.com/openai/v1", Hosted: true},
	"together":   {Name: "together", Label: "Together", BaseURL: "https://api.together.xyz/v1", Hosted: true},
	"ollama":     {Name: "ollama", Label: "Ollama", BaseURL: "http://localhost:11434/v1", Local: true},
	"llamacpp":   {Name: "llamacpp", Label: "llama.cpp", BaseURL: "http://localhost:8080/v1", Local: true},
	"vllm":       {Name: "vllm", Label: "vLLM", BaseURL: "http://localhost:8000/v1", Local: true},
	"lmstudio":   {Name: "lmstudio", Label: "LM Studio", BaseURL: "http://localhost:1234/v1", Local: true},
}

// ProviderNames returns every accepted -llm-provider value, sorted, for help
// text and validation.
func ProviderNames() []string {
	names := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// LookupProvider resolves a preset id.
func LookupProvider(name string) (Provider, bool) {
	provider, ok := providerRegistry[strings.ToLower(strings.TrimSpace(name))]

	return provider, ok
}

// IsOrcaRouter reports whether a provider id names OrcaRouter.
func IsOrcaRouter(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ProviderName)
}

// Config describes how to build the scan's llm client.
type Config struct {
	// Provider is the -llm-provider preset id.
	Provider string
	// BaseURL is -llm-base-url: any OpenAI-compatible endpoint. It overrides
	// the preset for every provider except OrcaRouter, whose inference origin
	// comes from the OrcaRouter overrides so the auth origin cannot drift.
	BaseURL string
	// Model is the model identifier. Empty selects the provider default.
	Model string

	// AuthBaseURL, APIBaseURL and SharedBaseURL are the OrcaRouter origin
	// overrides. Explicit per-origin values win over the shared value.
	AuthBaseURL   string
	APIBaseURL    string
	SharedBaseURL string

	// APIKey is an explicit credential. Empty falls back to the environment,
	// then to the stored credential.
	APIKey string
	// Store is the credential store. Nil uses the default location.
	Store *CredentialStore

	// Timeout bounds a single completion.
	Timeout time.Duration
	// Cache enables in-response caching.
	Cache bool
	// MaxCalls caps completions for the scan.
	MaxCalls int
	// MaxConcurrency caps in-flight completions.
	MaxConcurrency int

	// OnUnauthorized is called with the credential generation when the relay
	// rejects the credential as no longer valid. The caller decides what to
	// mark; this package never refreshes, because a PKCE-issued key is durable
	// and there is no refresh grant to call.
	OnUnauthorized func(generation int64)
}

// APIKeyEnvNames are the environment variables consulted for an OrcaRouter key,
// in precedence order. ORCAROUTER_API_KEY is the provider-specific name;
// LLM_API_KEY is the shared name the underlying client already documents.
var APIKeyEnvNames = []string{"ORCAROUTER_API_KEY", utilsllm.APIKeyEnv}

// APIKeyFromEnv returns the first configured OrcaRouter key from the
// environment.
func APIKeyFromEnv() string {
	for _, name := range APIKeyEnvNames {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}

	return ""
}

// New builds the scan's llm client.
//
// For OrcaRouter the credential is obtained through the CredentialSource seam,
// so a pasted key and a PKCE login are interchangeable here and nothing below
// this function knows which was used. For every other provider the call is a
// pass-through to the shared client, so existing behaviour is unchanged.
func New(config Config) (llmclient.Client, error) {
	if !IsOrcaRouter(config.Provider) {
		return newSharedClient(config)
	}

	endpoints := resolveEndpoints(config.AuthBaseURL, config.APIBaseURL, config.SharedBaseURL)
	if err := ValidateEndpoints(endpoints); err != nil {
		return nil, err
	}

	store := config.Store
	if store == nil {
		store = &CredentialStore{}
	}

	// Credential acquisition is the seam: an explicit key is one adapter, the
	// stored key a login wrote is the other, and neither the provider below nor
	// the model catalog is told which one produced it. The resolved key is
	// handed to the shared client directly rather than through a provider
	// preset, so the credential never depends on the shared table's
	// hosted-provider list.
	//
	// Precedence follows the repository's existing secret convention
	// (cli flag > env var > stored credential): an explicit --llm-api-key wins,
	// then ORCAROUTER_API_KEY / LLM_API_KEY, then the key a login stored.
	source := DefaultCredentialSource(firstNonEmpty(config.APIKey, APIKeyFromEnv()), store)
	credential, err := source.Credential()
	if err != nil {
		return nil, err
	}

	model := strings.TrimSpace(config.Model)
	if model == "" {
		model = DefaultModel
	}

	inner, err := utilsllm.New(utilsllm.Config{
		BaseURL:        endpoints.API,
		APIKey:         credential.Key,
		Model:          model,
		Timeout:        config.Timeout,
		Cache:          config.Cache,
		MaxCalls:       config.MaxCalls,
		MaxConcurrency: config.MaxConcurrency,
	})
	if err != nil {
		return nil, err
	}

	return &client{
		inner:          inner,
		model:          model,
		endpoints:      endpoints,
		store:          store,
		generation:     credential.Generation,
		source:         credential.Source,
		onUnauthorized: config.OnUnauthorized,
	}, nil
}

// newSharedClient builds a client for a non-OrcaRouter provider, preserving the
// existing behaviour of the shared provider layer.
//
// The shared client speaks utilsllm.Request, so it is adapted here rather than
// returned directly; that keeps the nuclei-side Client interface the one the
// matchers and extractors are written against.
func newSharedClient(config Config) (llmclient.Client, error) {
	inner, err := utilsllm.New(utilsllm.Config{
		Provider:       config.Provider,
		BaseURL:        config.BaseURL,
		APIKey:         firstNonEmpty(config.APIKey, APIKeyFromEnv()),
		Model:          config.Model,
		Timeout:        config.Timeout,
		Cache:          config.Cache,
		MaxCalls:       config.MaxCalls,
		MaxConcurrency: config.MaxConcurrency,
	})
	if err != nil {
		return nil, err
	}

	return &sharedClient{inner: inner, model: config.Model}, nil
}

// sharedClient adapts the shared provider client to the nuclei-side interface.
type sharedClient struct {
	inner *utilsllm.Client
	model string
}

// Complete implements llmclient.Client.
func (c *sharedClient) Complete(ctx context.Context, prompt string, asJSON bool) (string, error) {
	return c.inner.Complete(ctx, utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
}

// Model implements the model namer the matchers use for the audit record.
func (c *sharedClient) Model() string { return c.model }

// client wraps the shared OpenAI-compatible client with the OrcaRouter
// credential lifecycle: it knows which generation it was built with, and turns a
// relay 401 into a terminal reauthentication signal instead of a retry.
type client struct {
	inner      *utilsllm.Client
	model      string
	endpoints  Endpoints
	store      *CredentialStore
	generation int64
	source     Source

	onUnauthorized func(generation int64)
}

// Complete implements llmclient.Client.
func (c *client) Complete(ctx context.Context, prompt string, asJSON bool) (string, error) {
	answer, err := c.inner.Complete(ctx, utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
	if err != nil {
		if isUnauthorized(err) {
			c.markUnauthorized()
		}

		return "", err
	}

	return answer, nil
}

// Model names the model behind a verdict so it can be recorded in the finding.
func (c *client) Model() string { return c.model }

// CredentialSource names the authentication method this client was built from.
func (c *client) CredentialSource() Source { return c.source }

// CredentialGeneration is the stored generation this client is using. A late
// failure reports it so only the exact rejected credential is affected.
func (c *client) CredentialGeneration() int64 { return c.generation }

// Endpoints exposes the resolved origins, for diagnostics.
func (c *client) Endpoints() Endpoints { return c.endpoints }

// markUnauthorized records a terminal reauthentication requirement against the
// exact generation that made the rejected request.
func (c *client) markUnauthorized() {
	if c.store != nil {
		_, _ = c.store.MarkNeedsReauth(c.generation)
	}
	if c.onUnauthorized != nil {
		c.onUnauthorized(c.generation)
	}
}

// isUnauthorized reports whether a provider error is the relay rejecting the
// credential. The shared client renders a non-2xx status into its message, and
// 401 is the one status that means "reauthenticate" rather than "retry".
func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "status 401")
}

// DiscoverModels fetches the live catalog for the configured OrcaRouter origin
// using the scan's credential.
func DiscoverModels(ctx context.Context, endpoints Endpoints, apiKey string) Catalog {
	return DiscoverCatalog(ctx, nil, endpoints.API, apiKey)
}

// ModelsForFilter is a convenience for callers that want the filtered list and
// the catalog state together.
func ModelsForFilter(ctx context.Context, endpoints Endpoints, apiKey string, filter ModelFilter) ([]Model, Catalog) {
	catalog := DiscoverModels(ctx, endpoints, apiKey)

	return catalog.Filtered(filter), catalog
}

// ErrNoModelSelected is returned when an entry point has no compatible model.
var ErrNoModelSelected = errkit.New(
	"no orcarouter model is compatible with this entry point; run 'nuclei -llm-models' to list the available models",
)
