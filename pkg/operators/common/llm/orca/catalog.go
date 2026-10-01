package orca

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// Catalog bounds. A catalog response is remote input: it must not be able to
// consume unbounded memory or advertise routes this client cannot speak.
const (
	catalogTimeout      = 5 * time.Second
	maxCatalogBody      = 4 << 20
	maxCatalogModels    = 5000
	maxModelIDLength    = 200
	maxModelNameLength  = 200
	maxEndpointTypes    = 16
	maxInputModalities  = 8
	catalogMaxRetries   = 1
	catalogRetryBackoff = 250 * time.Millisecond
)

// Capability names a class of model an entry point can use. It mirrors the
// catalog's own capability vocabulary and the endpoint types this client can
// actually speak.
type Capability string

const (
	// CapabilityChat is text and multimodal chat.
	CapabilityChat Capability = "chat"
	// CapabilityEmbedding is vector embeddings.
	CapabilityEmbedding Capability = "embedding"
	// CapabilityImage is image generation.
	CapabilityImage Capability = "image"
	// CapabilityVideo is video generation.
	CapabilityVideo Capability = "video"
	// CapabilityRerank is reranking.
	CapabilityRerank Capability = "rerank"
)

// Endpoint types the client recognises. Anything outside this set is ignored
// rather than trusted, so a catalog cannot advertise a route we would mis-call.
const (
	endpointOpenAI         = "openai"
	endpointOpenAIResponse = "openai-response"
	endpointAnthropic      = "anthropic"
	endpointGemini         = "gemini"
	endpointEmbeddings     = "embeddings"
	endpointImageGen       = "image-generation"
	endpointOpenAIVideo    = "openai-video"
	endpointJinaRerank     = "jina-rerank"
)

// InputModality is a non-text input a chat model can accept.
type InputModality string

const (
	// ModalityText is always present on a chat model.
	ModalityText InputModality = "text"
	// ModalityImage is image input.
	ModalityImage InputModality = "image"
	// ModalityAudio is audio input.
	ModalityAudio InputModality = "audio"
	// ModalityVideo is video input.
	ModalityVideo InputModality = "video"
)

// Model is one catalog entry, reduced to the metadata the provider layer and a
// selector need.
type Model struct {
	// ID is the vendor/model identifier, preserved verbatim.
	ID string
	// Name is a display label.
	Name string
	// ContextLength is the advertised context window in tokens, 0 when unknown.
	ContextLength int
	// EndpointTypes are the endpoint types the catalog advertised.
	EndpointTypes []string
	// InputModalities are the advertised input modalities.
	InputModalities []InputModality
	// Reasoning reports whether the model advertises reasoning support.
	Reasoning bool
	// ReasoningEfforts are the advertised reasoning effort levels.
	ReasoningEfforts []string
	// Verified marks a model that came from the built-in seed rather than live
	// discovery. A selector can label these so a degraded catalog is visible.
	Verified bool
}

// SupportsImageInput reports whether the model explicitly declares image input.
func (m Model) SupportsImageInput() bool {
	return m.hasModality(ModalityImage)
}

// SupportsAudioInput reports whether the model explicitly declares audio input.
func (m Model) SupportsAudioInput() bool {
	return m.hasModality(ModalityAudio)
}

// SupportsVideoInput reports whether the model explicitly declares video input.
func (m Model) SupportsVideoInput() bool {
	return m.hasModality(ModalityVideo)
}

func (m Model) hasModality(modality InputModality) bool {
	for _, declared := range m.InputModalities {
		if declared == modality {
			return true
		}
	}

	return false
}

// hasEndpoint reports whether an endpoint type was advertised.
func (m Model) hasEndpoint(endpoint string) bool {
	for _, declared := range m.EndpointTypes {
		if declared == endpoint {
			return true
		}
	}

	return false
}

// ModelFilter is the capability requirement for one entry point.
type ModelFilter struct {
	// Capability is the class of model required.
	Capability Capability
	// RequireImageInput, RequireAudioInput and RequireVideoInput add a
	// multimodal requirement on top of CapabilityChat. A model that does not
	// declare the modality is excluded rather than assumed capable.
	RequireImageInput bool
	RequireAudioInput bool
	RequireVideoInput bool
}

// ChatFilter is the filter for nuclei's semantic-matching entry points: a text
// chat model.
func ChatFilter() ModelFilter {
	return ModelFilter{Capability: CapabilityChat}
}

// Accepts reports whether a model satisfies the filter.
//
// Every rule is a positive declaration in the catalog. A model that omits a
// field is not assumed to support it, so an unadvertised capability fails
// closed instead of being offered and then failing at request time.
func (f ModelFilter) Accepts(model Model) bool {
	switch f.Capability {
	case CapabilityChat:
		if !isChatEndpoint(model) {
			return false
		}
		if f.RequireImageInput && !model.SupportsImageInput() {
			return false
		}
		if f.RequireAudioInput && !model.SupportsAudioInput() {
			return false
		}
		if f.RequireVideoInput && !model.SupportsVideoInput() {
			return false
		}

		return true
	case CapabilityEmbedding:
		return model.hasEndpoint(endpointEmbeddings)
	case CapabilityImage:
		return model.hasEndpoint(endpointImageGen)
	case CapabilityVideo:
		return model.hasEndpoint(endpointOpenAIVideo)
	case CapabilityRerank:
		return model.hasEndpoint(endpointJinaRerank)
	default:
		return false
	}
}

// isChatEndpoint accepts the four chat wire protocols this client can speak and
// excludes the models whose endpoint types show they are dedicated to another
// task.
func isChatEndpoint(model Model) bool {
	for _, dedicated := range []string{endpointImageGen, endpointOpenAIVideo, endpointJinaRerank} {
		if model.hasEndpoint(dedicated) {
			return false
		}
	}

	for _, accepted := range []string{endpointOpenAI, endpointOpenAIResponse, endpointAnthropic, endpointGemini} {
		if model.hasEndpoint(accepted) {
			return true
		}
	}

	return false
}

// Filter returns the models satisfying the filter, sorted by id.
func Filter(models []Model, filter ModelFilter) []Model {
	accepted := make([]Model, 0, len(models))
	for _, model := range models {
		if filter.Accepts(model) {
			accepted = append(accepted, model)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].ID < accepted[j].ID })

	return accepted
}

// Catalog is a resolved model list plus where it came from.
type Catalog struct {
	// Models is the authoritative list when Live is true, otherwise the
	// verified fallback seed.
	Models []Model
	// Live reports whether live discovery succeeded.
	Live bool
	// Degraded reports that the fallback is in use and the caller should show
	// a refresh affordance.
	Degraded bool
	// Error is why live discovery failed, when it did.
	Error string
}

// Filtered returns the catalog entries satisfying a filter. When the catalog is
// degraded the result is the filtered seed, never a free-text fallback.
func (c Catalog) Filtered(filter ModelFilter) []Model {
	return Filter(c.Models, filter)
}

// DiscoverCatalog fetches the live model catalog for the configured origin and
// falls back to the verified seed on any failure.
//
// The returned models are the provider's own list; per-entry-point filtering is
// the caller's job through Catalog.Filtered.
func DiscoverCatalog(ctx context.Context, client *http.Client, apiBase, apiKey string) Catalog {
	models, err := fetchCatalog(ctx, client, apiBase, apiKey)
	if err != nil {
		return Catalog{
			Models:   SeedModels(),
			Live:     false,
			Degraded: true,
			Error:    err.Error(),
		}
	}

	return Catalog{Models: models, Live: true}
}

// fetchCatalog performs the bounded live request.
func fetchCatalog(ctx context.Context, client *http.Client, apiBase, apiKey string) ([]Model, error) {
	if strings.TrimSpace(apiBase) == "" {
		return nil, errkit.New("orcarouter api base url is empty")
	}
	if client == nil {
		client = &http.Client{Timeout: catalogTimeout}
	}

	var lastErr error
	for attempt := 0; attempt <= catalogMaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(catalogRetryBackoff):
			}
		}

		models, err := fetchCatalogOnce(ctx, client, apiBase, apiKey)
		if err == nil {
			return models, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

func fetchCatalogOnce(ctx context.Context, client *http.Client, apiBase, apiKey string) ([]Model, error) {
	if client == nil {
		client = &http.Client{Timeout: catalogTimeout}
	}

	requestCtx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()

	endpoint := strings.TrimSuffix(apiBase, "/") + ModelsPath + "?" +
		url.Values{"capability": {string(CapabilityChat)}}.Encode()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errkit.Wrap(err, "could not build the orcarouter model request")
	}
	request.Header.Set("Accept", "application/json")
	if strings.TrimSpace(apiKey) != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, errkit.Wrap(err, "could not reach the orcarouter model catalog")
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxCatalogBody))
	if err != nil {
		return nil, errkit.Wrap(err, "could not read the orcarouter model catalog")
	}
	if response.StatusCode != http.StatusOK {
		return nil, errkit.Newf(
			"orcarouter model catalog returned status %d",
			response.StatusCode,
		)
	}

	return parseCatalog(body)
}

// catalogEnvelope is the documented list shape. Additional keys are ignored.
type catalogEnvelope struct {
	Data []catalogEntry `json:"data"`
}

type catalogEntry struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	ContextLength       int             `json:"context_length"`
	SupportedEndpoint   json.RawMessage `json:"supported_endpoint_types"`
	Architecture        *architecture   `json:"architecture"`
	Reasoning           json.RawMessage `json:"reasoning"`
	ReasoningEfforts    json.RawMessage `json:"reasoning_efforts"`
	SupportedParameters json.RawMessage `json:"supported_parameters"`
}

type architecture struct {
	InputModalities json.RawMessage `json:"input_modalities"`
}

// parseCatalog validates and reduces a catalog body. Records that do not have
// the accepted shape are skipped rather than failing the whole catalog, which is
// what lets one malformed record coexist with a usable list.
func parseCatalog(body []byte) ([]Model, error) {
	var envelope catalogEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errkit.Wrap(err, "the orcarouter model catalog was not valid json")
	}

	models := make([]Model, 0, len(envelope.Data))
	seen := make(map[string]struct{}, len(envelope.Data))

	for _, entry := range envelope.Data {
		if len(models) >= maxCatalogModels {
			break
		}

		id := strings.TrimSpace(entry.ID)
		if id == "" || len(id) > maxModelIDLength {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}

		model := Model{
			ID:            id,
			Name:          truncate(strings.TrimSpace(entry.Name), maxModelNameLength),
			ContextLength: entry.ContextLength,
		}
		if model.Name == "" {
			model.Name = id
		}

		model.EndpointTypes = parseStringList(entry.SupportedEndpoint, maxEndpointTypes)
		model.Reasoning, model.ReasoningEfforts = parseReasoning(entry)
		if entry.Architecture != nil {
			model.InputModalities = parseModalities(entry.Architecture.InputModalities)
		}

		models = append(models, model)
	}

	return models, nil
}

// parseReasoning reads the two shapes a catalog uses to advertise reasoning: a
// boolean or object under "reasoning", and an explicit effort list under
// "reasoning_efforts" or in the supported-parameters list.
func parseReasoning(entry catalogEntry) (bool, []string) {
	reasoning := false
	if len(entry.Reasoning) > 0 {
		var flag bool
		if err := json.Unmarshal(entry.Reasoning, &flag); err == nil {
			reasoning = flag
		} else {
			var object struct {
				Supported bool `json:"supported"`
				Enabled   bool `json:"enabled"`
			}
			if err := json.Unmarshal(entry.Reasoning, &object); err == nil {
				reasoning = object.Supported || object.Enabled
			}
		}
	}

	efforts := parseStringList(entry.ReasoningEfforts, 8)
	if len(efforts) == 0 {
		for _, parameter := range parseStringList(entry.SupportedParameters, 64) {
			if strings.HasPrefix(parameter, "reasoning_effort") || parameter == "reasoning" {
				reasoning = true
			}
		}
	}
	if len(efforts) > 0 {
		reasoning = true
	}

	return reasoning, efforts
}

// parseStringList decodes either a JSON array of strings or a single string.
func parseStringList(raw json.RawMessage, limit int) []string {
	if len(raw) == 0 {
		return nil
	}

	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil
		}
		values = []string{single}
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}

	return out
}

// parseModalities decodes the architecture input modalities.
func parseModalities(raw json.RawMessage) []InputModality {
	values := parseStringList(raw, maxInputModalities)
	if len(values) == 0 {
		return nil
	}

	modalities := make([]InputModality, 0, len(values))
	for _, value := range values {
		modalities = append(modalities, InputModality(strings.ToLower(value)))
	}

	return modalities
}

// seedModels is the verified fallback catalog, used only when live discovery
// fails. It is deliberately small so a fresh installation can start during an
// outage without pretending to be the authoritative list.
//
// Verification source: GET https://api.orcarouter.ai/v1/models?capability=chat.
// `deepseek/deepseek-v4-pro`, `deepseek/deepseek-v4.1-flash` and
// `orcarouter/auto` were observed there and carry exactly the advertised
// metadata. The three vendor models are the campaign's documented verified seed
// and are retained so a cold start still offers a recognisable list; their
// advertised context length was not observable from this workspace, so it is
// left unset rather than guessed. Only the reasoning ladder and input
// modalities that were verified are recorded.
var seedModels = []Model{
	{
		ID:               "openai/gpt-5.5",
		Name:             "GPT-5.5",
		EndpointTypes:    []string{endpointOpenAI, endpointOpenAIResponse},
		InputModalities:  []InputModality{ModalityText, ModalityImage},
		Reasoning:        true,
		ReasoningEfforts: []string{"low", "medium", "high", "xhigh"},
		Verified:         true,
	},
	{
		ID:              "anthropic/claude-opus-4.8",
		Name:            "Claude Opus 4.8",
		EndpointTypes:   []string{endpointAnthropic, endpointOpenAI},
		InputModalities: []InputModality{ModalityText, ModalityImage},
		Reasoning:       true,
		Verified:        true,
	},
	{
		ID:              "google/gemini-3.5-flash",
		Name:            "Gemini 3.5 Flash",
		EndpointTypes:   []string{endpointGemini, endpointOpenAI},
		InputModalities: []InputModality{ModalityText, ModalityImage},
		Verified:        true,
	},
	{
		ID:              "deepseek/deepseek-v4-pro",
		Name:            "DeepSeek V4 Pro",
		ContextLength:   1048576,
		EndpointTypes:   []string{endpointOpenAI, endpointOpenAIResponse},
		InputModalities: []InputModality{ModalityText},
		Verified:        true,
	},
	{
		ID:              "deepseek/deepseek-v4.1-flash",
		Name:            "DeepSeek V4.1 Flash",
		ContextLength:   1048576,
		EndpointTypes:   []string{endpointOpenAI, endpointOpenAIResponse, endpointAnthropic},
		InputModalities: []InputModality{ModalityText, ModalityImage},
		Verified:        true,
	},
	{
		ID:              "orcarouter/auto",
		Name:            "OrcaRouter Auto",
		EndpointTypes:   []string{endpointOpenAI, endpointOpenAIResponse, endpointAnthropic, endpointGemini},
		InputModalities: []InputModality{ModalityText},
		Verified:        true,
	},
}

// SeedModels returns a copy of the verified fallback catalog so a caller cannot
// mutate the package-level seed.
func SeedModels() []Model {
	out := make([]Model, len(seedModels))
	for i, model := range seedModels {
		out[i] = model
		out[i].EndpointTypes = append([]string(nil), model.EndpointTypes...)
		out[i].InputModalities = append([]InputModality(nil), model.InputModalities...)
		out[i].ReasoningEfforts = append([]string(nil), model.ReasoningEfforts...)
	}

	return out
}
