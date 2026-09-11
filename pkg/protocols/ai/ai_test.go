package ai

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

const testSharedPrompt = "find exposed admin panels"

const validFragment = `http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
`

type stubResolver struct {
	fragment string
	calls    int
}

func (resolver *stubResolver) Resolve(_ context.Context, _ string, _ string) ([]byte, error) {
	resolver.calls++

	return []byte(resolver.fragment), nil
}

func expandOptions(t *testing.T, resolver Resolver) ExpandOptions {
	t.Helper()

	return ExpandOptions{
		Resolver: func() (Resolver, error) { return resolver, nil },
		Store:    NewStore(t.TempDir()),
	}
}

func TestCacheKeyIgnoresSurroundingWhitespace(t *testing.T) {
	first := &Request{Prompt: "find exposed admin panels"}
	second := &Request{Prompt: "  find exposed admin panels\n"}

	require.Equal(t, first.CacheKey("gpt-4o"), second.CacheKey("gpt-4o"))
}

func TestCacheKeyChangesWithModel(t *testing.T) {
	request := &Request{Prompt: "find exposed admin panels"}

	require.NotEqual(t, request.CacheKey("gpt-4o"), request.CacheKey("qwen3-vl"),
		"different resolver models must not share a cache entry")
}

func TestEffectiveModelPrefersTheTemplate(t *testing.T) {
	require.Equal(t, "qwen3-vl", (&Request{Model: "qwen3-vl"}).EffectiveModel("gpt-4o"))
	require.Equal(t, "gpt-4o", (&Request{}).EffectiveModel("gpt-4o"))
}

func TestResolverDefaultModelReachesTheCacheKey(t *testing.T) {
	first := &stubResolver{fragment: validFragment}
	options := ExpandOptions{
		Resolver: func() (Resolver, error) { return first, nil },
		Store:    NewStore(t.TempDir()),
		Model:    "gpt-4o",
	}

	_, err := (&Request{Prompt: testSharedPrompt}).Expand(context.Background(), options)
	require.NoError(t, err)

	second := &stubResolver{fragment: validFragment}
	options.Resolver = func() (Resolver, error) { return second, nil }
	options.Model = "qwen3-vl"

	_, err = (&Request{Prompt: testSharedPrompt}).Expand(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, 1, second.calls, "switching model must re-resolve, not reuse the other model's fragment")
}

func TestExpandResolvesOncePerPrompt(t *testing.T) {
	resolver := &stubResolver{fragment: validFragment}
	options := expandOptions(t, resolver)

	for range 3 {
		request := &Request{Prompt: "find exposed admin panels"}

		fragment, err := request.Expand(context.Background(), options)
		require.NoError(t, err)
		require.Len(t, fragment.HTTP, 1)
	}

	require.Equal(t, 1, resolver.calls, "cached prompts must not reach the resolver again")
}

func TestExpandWithWarmCacheNeedsNoResolver(t *testing.T) {
	options := expandOptions(t, &stubResolver{fragment: validFragment})

	request := &Request{Prompt: "find exposed admin panels"}
	_, err := request.Expand(context.Background(), options)
	require.NoError(t, err)

	offline := ExpandOptions{Store: options.Store}

	fragment, err := (&Request{Prompt: "find exposed admin panels"}).Expand(context.Background(), offline)
	require.NoError(t, err)
	require.Len(t, fragment.HTTP, 1)
}

func TestExpandPinsTheFragmentNotThePrompt(t *testing.T) {
	request := &Request{Prompt: "find exposed admin panels"}

	_, err := request.Expand(context.Background(), expandOptions(t, &stubResolver{fragment: validFragment}))
	require.NoError(t, err)
	require.Equal(t, FragmentDigest([]byte(validFragment)), request.Expansion)
}

func TestPinSurvivesADifferentModelProducingTheSameFragment(t *testing.T) {
	pinned := &Request{Prompt: "find exposed admin panels", Expansion: FragmentDigest([]byte(validFragment))}

	options := expandOptions(t, &stubResolver{fragment: validFragment})
	options.Model = "some-other-model"

	_, err := pinned.Expand(context.Background(), options)
	require.NoError(t, err, "a pin must not be tied to the model that produced it")
}

func TestExpandRejectsMismatchedPin(t *testing.T) {
	request := &Request{Prompt: "find exposed admin panels", Expansion: "stale"}

	_, err := request.Expand(context.Background(), expandOptions(t, &stubResolver{fragment: validFragment}))
	require.ErrorContains(t, err, "regenerate the template")
}

func TestExpandRejectsFragmentWithoutMatchers(t *testing.T) {
	fragment := `http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
`
	request := &Request{Prompt: "find exposed admin panels"}

	_, err := request.Expand(context.Background(), expandOptions(t, &stubResolver{fragment: fragment}))
	require.ErrorContains(t, err, "defines no matchers")
}

func TestExpandRejectsUnsupportedProtocolKeys(t *testing.T) {
	fragment := `code:
  - engine:
      - sh
    source: id
`
	request := &Request{Prompt: "run id on the target"}

	_, err := request.Expand(context.Background(), expandOptions(t, &stubResolver{fragment: fragment}))
	require.ErrorContains(t, err, "unsupported key")
}

func TestExpandRejectsEmptyPrompt(t *testing.T) {
	request := &Request{Prompt: "   "}

	_, err := request.Expand(context.Background(), expandOptions(t, &stubResolver{fragment: validFragment}))
	require.ErrorContains(t, err, "no prompt")
}

func TestStripCodeFence(t *testing.T) {
	require.Equal(t, "http: []", stripCodeFence("```yaml\nhttp: []\n```"))
	require.Equal(t, "http: []", stripCodeFence("http: []"))
}

func TestNewResolverDefaultsToOpenAI(t *testing.T) {
	resolver, err := NewResolver(ProviderConfig{Model: "gpt-4o"})
	require.NoError(t, err, "an SDK caller setting only a model must behave like the CLI default")
	require.NotNil(t, resolver)
}

func TestNewResolverRejectsUnknownProvider(t *testing.T) {
	_, err := NewResolver(ProviderConfig{Provider: "nope", Model: "gpt-4o"})
	require.ErrorContains(t, err, "unknown ai provider")
}

func TestNewResolverRequiresAModel(t *testing.T) {
	_, err := NewResolver(ProviderConfig{Provider: "ollama"})
	require.ErrorContains(t, err, "no ai model configured")
}

func TestNewResolverDispatchesAnthropicToMessagesAPI(t *testing.T) {
	resolver, err := NewResolver(ProviderConfig{Provider: "anthropic", Model: "claude-opus-5"})
	require.NoError(t, err)
	require.IsType(t, &anthropicResolver{}, resolver)
}

func TestNewResolverDispatchesPresetsToChatCompletions(t *testing.T) {
	for _, provider := range []string{"openai", "ollama", "groq", "vllm"} {
		resolver, err := NewResolver(ProviderConfig{Provider: provider, Model: "any"})
		require.NoError(t, err, provider)
		require.IsType(t, &openAIResolver{}, resolver, provider)
	}
}

func TestBaseURLOverridesAnthropicDispatch(t *testing.T) {
	// a base url means the caller is pointing at an OpenAI compatible gateway,
	// whatever they named the provider
	resolver, err := NewResolver(ProviderConfig{Provider: "anthropic", BaseURL: "http://localhost:8080/v1", Model: "any"})
	require.NoError(t, err)
	require.IsType(t, &openAIResolver{}, resolver)
}

func TestProviderNamesIncludesAnthropic(t *testing.T) {
	require.Contains(t, ProviderNames(), "anthropic")
	require.IsIncreasing(t, ProviderNames())
}
