package orca

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// liveCatalogFixture covers every capability the filter distinguishes: a
// text-only chat model, an image-input chat model, an embedding model, an image
// generation model, a video model, and a rerank model.
const liveCatalogFixture = `{
  "data": [
    {"id":"openai/gpt-5.5","name":"GPT-5.5","context_length":400000,
     "supported_endpoint_types":["openai","openai-response"],
     "architecture":{"input_modalities":["text","image"]},
     "reasoning":true,"reasoning_efforts":["low","medium","high","xhigh"]},
    {"id":"deepseek/deepseek-v4-pro","name":"DeepSeek V4 Pro","context_length":128000,
     "supported_endpoint_types":["openai"],
     "architecture":{"input_modalities":["text"]},
     "supported_parameters":["reasoning_effort"]},
    {"id":"anthropic/claude-opus-4.8","name":"Claude Opus 4.8","context_length":200000,
     "supported_endpoint_types":["anthropic"],
     "architecture":{"input_modalities":["text","image"]},"reasoning":{"supported":true}},
    {"id":"google/gemini-3.5-flash","name":"Gemini 3.5 Flash","context_length":1000000,
     "supported_endpoint_types":["gemini"],"architecture":{"input_modalities":["text","image"]}},
    {"id":"orcarouter/auto","name":"OrcaRouter Auto","context_length":200000,
     "supported_endpoint_types":["openai"],"architecture":{"input_modalities":["text"]}},
    {"id":"openai/text-embedding-3-large","name":"Embedding 3 Large",
     "supported_endpoint_types":["embeddings"]},
    {"id":"openai/gpt-image-1","name":"GPT Image 1",
     "supported_endpoint_types":["image-generation"]},
    {"id":"openai/sora-2","name":"Sora 2","supported_endpoint_types":["openai-video"]},
    {"id":"jina/jina-reranker-v3","name":"Jina Reranker v3",
     "supported_endpoint_types":["jina-rerank"]},
    {"id":"mystery/unadvertised","name":"Mystery","architecture":{"input_modalities":["text"]}},
    {"id":"","name":"no id"},
    {"id":"broken/no-endpoints"}
  ]
}`

func catalogFromFixture(t *testing.T, body string) []Model {
	t.Helper()

	models, err := parseCatalog([]byte(body))
	require.NoError(t, err)

	return models
}

// TestParseCatalogReducesRecordsAndSkipsMalformed proves parsing keeps the
// documented metadata, drops records with no usable id, and does not fail the
// whole catalog over one bad record.
func TestParseCatalogReducesRecordsAndSkipsMalformed(t *testing.T) {
	models := catalogFromFixture(t, liveCatalogFixture)

	ids := SortedModelIDs(models)
	require.Contains(t, ids, "openai/gpt-5.5")
	require.Contains(t, ids, "deepseek/deepseek-v4-pro")
	require.NotContains(t, ids, "", "a record with no id is skipped")
	require.Len(t, models, 11)

	byID := map[string]Model{}
	for _, model := range models {
		byID[model.ID] = model
	}

	gpt := byID["openai/gpt-5.5"]
	require.Equal(t, "GPT-5.5", gpt.Name)
	require.Equal(t, 400000, gpt.ContextLength)
	require.True(t, gpt.Reasoning)
	require.Equal(t, []string{"low", "medium", "high", "xhigh"}, gpt.ReasoningEfforts)
	require.True(t, gpt.SupportsImageInput())
	require.False(t, gpt.Verified, "a live model is not a verified fallback")

	// Reasoning can be advertised as a supported parameter instead of a flag.
	require.True(t, byID["deepseek/deepseek-v4-pro"].Reasoning)
	require.False(t, byID["deepseek/deepseek-v4-pro"].SupportsImageInput())
	// Or as an object with supported/enabled.
	require.True(t, byID["anthropic/claude-opus-4.8"].Reasoning)
	// A model with no endpoint types is kept but matches no capability.
	require.Empty(t, byID["broken/no-endpoints"].EndpointTypes)
}

// TestParseCatalogRejectsNonJSON proves a broken body is an error rather than an
// empty catalog that would look like "no models".
func TestParseCatalogRejectsNonJSON(t *testing.T) {
	_, err := parseCatalog([]byte("<html>not json</html>"))
	require.Error(t, err)
}

// TestFilterChatExcludesNonChatModels is the capability rule for nuclei's entry
// points: only models that can serve text chat.
func TestFilterChatExcludesNonChatModels(t *testing.T) {
	models := catalogFromFixture(t, liveCatalogFixture)
	chat := SortedModelIDs(Filter(models, ChatFilter()))

	require.Contains(t, chat, "openai/gpt-5.5")
	require.Contains(t, chat, "deepseek/deepseek-v4-pro")
	require.Contains(t, chat, "anthropic/claude-opus-4.8")
	require.Contains(t, chat, "google/gemini-3.5-flash")
	require.Contains(t, chat, "orcarouter/auto")

	require.NotContains(t, chat, "openai/text-embedding-3-large")
	require.NotContains(t, chat, "openai/gpt-image-1")
	require.NotContains(t, chat, "openai/sora-2")
	require.NotContains(t, chat, "jina/jina-reranker-v3")
	require.NotContains(t, chat, "mystery/unadvertised",
		"a model that advertises no endpoint type must not be offered")
	require.NotContains(t, chat, "broken/no-endpoints")
}

// TestFilterByCapability proves each capability selects only its own models.
func TestFilterByCapability(t *testing.T) {
	models := catalogFromFixture(t, liveCatalogFixture)

	cases := []struct {
		capability Capability
		expected   string
		excluded   string
	}{
		{CapabilityEmbedding, "openai/text-embedding-3-large", "openai/gpt-5.5"},
		{CapabilityImage, "openai/gpt-image-1", "openai/gpt-5.5"},
		{CapabilityVideo, "openai/sora-2", "openai/gpt-5.5"},
		{CapabilityRerank, "jina/jina-reranker-v3", "openai/gpt-5.5"},
	}

	for _, testCase := range cases {
		t.Run(string(testCase.capability), func(t *testing.T) {
			ids := SortedModelIDs(Filter(models, ModelFilter{Capability: testCase.capability}))
			require.Equal(t, []string{testCase.expected}, ids)
			require.NotContains(t, ids, testCase.excluded)
		})
	}

	require.Empty(t, Filter(models, ModelFilter{Capability: "unknown"}))
}

// TestMultimodalFilterFailsClosed proves an image requirement keeps only models
// that explicitly declare image input.
func TestMultimodalFilterFailsClosed(t *testing.T) {
	models := catalogFromFixture(t, liveCatalogFixture)
	multimodal := SortedModelIDs(Filter(models, ModelFilter{
		Capability:        CapabilityChat,
		RequireImageInput: true,
	}))

	require.Equal(t, []string{
		"anthropic/claude-opus-4.8",
		"google/gemini-3.5-flash",
		"openai/gpt-5.5",
	}, multimodal)

	// Text-only chat models are excluded rather than assumed capable.
	require.NotContains(t, multimodal, "deepseek/deepseek-v4-pro")
	require.NotContains(t, multimodal, "orcarouter/auto")
	require.NotContains(t, multimodal, "mystery/unadvertised")

	// A modality nothing advertises yields nothing rather than everything.
	require.Empty(t, Filter(models, ModelFilter{Capability: CapabilityChat, RequireAudioInput: true}))
	require.Empty(t, Filter(models, ModelFilter{Capability: CapabilityChat, RequireVideoInput: true}))
}

// TestFilterIsStableAndSorted proves the selector input has a deterministic
// order.
func TestFilterIsStableAndSorted(t *testing.T) {
	models := catalogFromFixture(t, liveCatalogFixture)
	first := SortedModelIDs(Filter(models, ChatFilter()))
	second := SortedModelIDs(Filter(models, ChatFilter()))
	require.Equal(t, first, second)
}

// TestDiscoverCatalogFallsBackToVerifiedSeed proves a catalog failure yields the
// labelled fallback, never an empty list and never free text.
func TestDiscoverCatalogFallsBackToVerifiedSeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, "boom")
	}))
	defer server.Close()

	catalog := DiscoverCatalog(context.Background(), server.Client(), server.URL, "sk-orca-test")
	require.False(t, catalog.Live)
	require.True(t, catalog.Degraded, "a degraded catalog must be visible to the caller")
	require.NotEmpty(t, catalog.Error)

	models := catalog.Filtered(ChatFilter())
	require.Len(t, models, len(seedModels))
	for _, model := range models {
		require.True(t, model.Verified, "a fallback entry must be marked verified")
	}
}

// TestSeedKeepsVerifiedMetadata proves the fallback preserves the reasoning
// ladder and input modalities that were verified against the live catalog.
func TestSeedKeepsVerifiedMetadata(t *testing.T) {
	seed := SeedModels()
	byID := map[string]Model{}
	for _, model := range seed {
		byID[model.ID] = model
	}

	gpt, ok := byID["openai/gpt-5.5"]
	require.True(t, ok)
	require.Equal(t, []string{"low", "medium", "high", "xhigh"}, gpt.ReasoningEfforts)
	require.True(t, gpt.SupportsImageInput())
	require.True(t, gpt.Reasoning)

	for _, id := range []string{
		"openai/gpt-5.5",
		"anthropic/claude-opus-4.8",
		"google/gemini-3.5-flash",
		"deepseek/deepseek-v4-pro",
		"orcarouter/auto",
	} {
		require.Contains(t, byID, id)
	}

	// The seed must not mutate when a caller edits its copy.
	seed[0].ID = "mutated"
	seed[0].EndpointTypes[0] = "mutated"
	require.Equal(t, "openai/gpt-5.5", SeedModels()[0].ID)
	require.Equal(t, endpointOpenAI, SeedModels()[0].EndpointTypes[0])
}

// TestLiveCatalogIsAuthoritativeOverSeed proves a successful discovery is not
// diluted with fallback entries.
func TestLiveCatalogIsAuthoritativeOverSeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/models", request.URL.Path)
		require.Equal(t, "chat", request.URL.Query().Get("capability"))
		require.Equal(t, "Bearer sk-orca-live", request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"data":[{"id":"vendor/only-live","supported_endpoint_types":["openai"]}]}`)
	}))
	defer server.Close()

	catalog := DiscoverCatalog(context.Background(), server.Client(), server.URL, "sk-orca-live")
	require.True(t, catalog.Live)
	require.False(t, catalog.Degraded)

	ids := SortedModelIDs(catalog.Filtered(ChatFilter()))
	require.Equal(t, []string{"vendor/only-live"}, ids)
	require.NotContains(t, ids, "openai/gpt-5.5", "the seed must not be mixed into a live result")
}

// TestCatalogRequestIsBounded proves an oversized response cannot be read
// without limit.
func TestCatalogRequestIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"data":[`)
		chunk := strings.Repeat("x", 1<<20)
		for i := 0; i < 8; i++ {
			_, _ = io.WriteString(writer, chunk)
		}
		_, _ = io.WriteString(writer, `]}`)
	}))
	defer server.Close()

	// The body is truncated at the bound, so the JSON is incomplete and the
	// result is the degraded seed rather than an unbounded read.
	catalog := DiscoverCatalog(context.Background(), server.Client(), server.URL, "sk-orca-test")
	require.False(t, catalog.Live)
	require.True(t, catalog.Degraded)
}

// TestCatalogModelCountIsBounded proves the accepted item count is capped.
func TestCatalogModelCountIsBounded(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"data":[`)
	for i := 0; i < maxCatalogModels+50; i++ {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(`{"id":"vendor/model-`)
		builder.WriteString(strings.Repeat("0", 1))
		builder.WriteString(itoa(i))
		builder.WriteString(`","supported_endpoint_types":["openai"]}`)
	}
	builder.WriteString(`]}`)

	models, err := parseCatalog([]byte(builder.String()))
	require.NoError(t, err)
	require.LessOrEqual(t, len(models), maxCatalogModels)
}

// TestCatalogRejectsOverlongIDs proves an absurd id cannot be accepted.
func TestCatalogRejectsOverlongIDs(t *testing.T) {
	body := `{"data":[{"id":"` + strings.Repeat("a", maxModelIDLength+1) + `","supported_endpoint_types":["openai"]}]}`
	models, err := parseCatalog([]byte(body))
	require.NoError(t, err)
	require.Empty(t, models)
}

// TestCatalogErrorIsNotLeakedIntoModels proves a failure is reported as state,
// not as a fake model entry.
func TestCatalogErrorIsNotLeakedIntoModels(t *testing.T) {
	catalog := DiscoverCatalog(context.Background(), nil, "http://127.0.0.1:1/v1", "sk-orca-test")
	require.False(t, catalog.Live)

	for _, model := range catalog.Filtered(ChatFilter()) {
		require.NotContains(t, model.ID, "error")
		require.NotEmpty(t, model.ID)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}

	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}

	return string(digits)
}

// TestCatalogTimeoutIsBounded proves a hanging endpoint does not hang the caller
// indefinitely.
func TestCatalogTimeoutIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*catalogTimeout)
	defer cancel()

	catalog := DiscoverCatalog(ctx, server.Client(), server.URL, "sk-orca-test")
	require.False(t, catalog.Live)
	require.True(t, catalog.Degraded)
	require.NotEmpty(t, catalog.Error)
}

// TestDiscoverCatalogRejectsEmptyOrigin proves a missing origin is an error
// rather than a request to a relative path.
func TestDiscoverCatalogRejectsEmptyOrigin(t *testing.T) {
	catalog := DiscoverCatalog(context.Background(), nil, "", "sk-orca-test")
	require.False(t, catalog.Live)
	require.True(t, catalog.Degraded)

	_, err := fetchCatalog(context.Background(), nil, "  ", "")
	require.Error(t, err)
}

// TestFilteredCatalogFromSeedIsUsableWithoutCredentials proves a fresh
// installation can show a usable selector during an outage.
func TestFilteredCatalogFromSeedIsUsableWithoutCredentials(t *testing.T) {
	catalog := Catalog{Models: SeedModels(), Live: false, Degraded: true}
	models := catalog.Filtered(ChatFilter())
	require.NotEmpty(t, models)

	multimodal := catalog.Filtered(ModelFilter{Capability: CapabilityChat, RequireImageInput: true})
	require.NotEmpty(t, multimodal)
	require.NotContains(t, SortedModelIDs(multimodal), "deepseek/deepseek-v4-pro")

	// Embedding is genuinely absent from the verified seed, so it must be empty
	// rather than filled with chat models.
	require.Empty(t, catalog.Filtered(ModelFilter{Capability: CapabilityEmbedding}))
}

// TestParseStringListHandlesBothShapes proves the two catalog encodings are
// both accepted and bounded.
func TestParseStringListHandlesBothShapes(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, parseStringList([]byte(`["a","b"]`), 8))
	require.Equal(t, []string{"solo"}, parseStringList([]byte(`"solo"`), 8))
	require.Nil(t, parseStringList([]byte(`{"nope":1}`), 8))
	require.Nil(t, parseStringList(nil, 8))
	require.Equal(t, []string{"a"}, parseStringList([]byte(`["a","b"]`), 1))
}

// TestParseModalitiesLowercases proves modality matching is case-insensitive.
func TestParseModalitiesLowercases(t *testing.T) {
	require.Equal(t, []InputModality{ModalityText, ModalityImage},
		parseModalities([]byte(`["Text","IMAGE"]`)))
	require.Nil(t, parseModalities(nil))
}

// TestFilterAcceptsIsDeclarative proves an empty model satisfies nothing.
func TestFilterAcceptsIsDeclarative(t *testing.T) {
	require.False(t, ChatFilter().Accepts(Model{}))
	require.False(t, ChatFilter().Accepts(Model{EndpointTypes: []string{"embeddings"}}))
	require.True(t, ChatFilter().Accepts(Model{EndpointTypes: []string{"openai"}}))
	require.True(t, ChatFilter().Accepts(Model{EndpointTypes: []string{"openai-response"}}))
	require.True(t, ChatFilter().Accepts(Model{EndpointTypes: []string{"anthropic"}}))
	require.True(t, ChatFilter().Accepts(Model{EndpointTypes: []string{"gemini"}}))
}

// TestCatalogErrorIsAnError proves the degraded catalog still exposes a
// diagnosable cause.
func TestCatalogErrorIsAnError(t *testing.T) {
	_, err := fetchCatalogOnce(context.Background(), nil, "http://127.0.0.1:1", "")
	require.Error(t, err)
	require.False(t, errors.Is(err, context.Canceled))
}
