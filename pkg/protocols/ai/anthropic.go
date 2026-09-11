package ai

import (
	"context"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/projectdiscovery/utils/errkit"
)

// anthropicResolver talks to the Messages API.
//
// It needs its own client rather than a base url because the wire format
// differs from chat completions: the system prompt is a top-level field, auth
// is x-api-key, and responses arrive as content blocks.
type anthropicResolver struct {
	client anthropic.Client
	model  string
}

func newAnthropicResolver(model, apiKey string, timeout time.Duration) *anthropicResolver {
	options := []option.RequestOption{option.WithRequestTimeout(timeout)}
	// an empty key would override the SDK's own credential resolution, which
	// also reads ANTHROPIC_API_KEY and the logged-in profile
	if apiKey != "" {
		options = append(options, option.WithAPIKey(apiKey))
	}

	return &anthropicResolver{client: anthropic.NewClient(options...), model: model}
}

// Resolve maps a prompt onto nuclei protocol primitives.
func (resolver *anthropicResolver) Resolve(ctx context.Context, prompt string, model string) ([]byte, error) {
	if model == "" {
		model = resolver.model
	}

	fragment, err := resolver.complete(ctx, model, prompt)
	if err != nil {
		return nil, err
	}

	if parseErr := validateFragment(fragment); parseErr != nil {
		if fragment, err = resolver.complete(ctx, model, retryPrompt(prompt, parseErr)); err != nil {
			return nil, err
		}
		if parseErr = validateFragment(fragment); parseErr != nil {
			return nil, errkit.Wrap(parseErr, "resolver did not return a usable fragment")
		}
	}

	return fragment, nil
}

func (resolver *anthropicResolver) complete(ctx context.Context, model, prompt string) ([]byte, error) {
	// no temperature: sampling parameters are rejected on current Claude
	// models, and the capability contract is what constrains the output shape
	response, err := resolver.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: maxResponseTokens,
		System:    []anthropic.TextBlockParam{{Text: capabilityContract}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, errkit.Wrap(err, "could not reach ai provider")
	}

	if response.StopReason == anthropic.StopReasonRefusal {
		return nil, errkit.Newf("ai provider declined the prompt (%s)", response.StopDetails.Category)
	}

	var builder strings.Builder
	for _, block := range response.Content {
		if text, ok := block.AsAny().(anthropic.TextBlock); ok {
			builder.WriteString(text.Text)
		}
	}

	if builder.Len() == 0 {
		return nil, errkit.New("ai provider returned no text content")
	}

	return []byte(stripCodeFence(builder.String())), nil
}
