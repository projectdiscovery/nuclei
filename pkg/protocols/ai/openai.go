package ai

import (
	"context"
	"net/http"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	openai "github.com/sashabaranov/go-openai"
)

// openAIResolver talks to any /v1/chat/completions endpoint.
//
// That one wire format covers every local runtime (ollama, llama.cpp, vLLM,
// LM Studio) alongside the hosted providers, so offline use is the same code
// path as frontier use rather than a bolted-on special case.
type openAIResolver struct {
	client *openai.Client
	model  string
}

func newOpenAIResolver(baseURL, model, apiKey string, timeout time.Duration) *openAIResolver {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseURL
	config.HTTPClient = &http.Client{Timeout: timeout}

	return &openAIResolver{client: openai.NewClientWithConfig(config), model: model}
}

// Resolve maps a prompt onto nuclei protocol primitives.
func (resolver *openAIResolver) Resolve(ctx context.Context, prompt string, model string) ([]byte, error) {
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

func (resolver *openAIResolver) complete(ctx context.Context, model, prompt string) ([]byte, error) {
	// temperature 0 so that a cache miss on the same prompt tends to produce
	// the same fragment, which keeps template review meaningful
	response, err := resolver.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:       model,
		MaxTokens:   maxResponseTokens,
		Temperature: 0,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: capabilityContract},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		return nil, errkit.Wrap(err, "could not reach ai provider")
	}

	if len(response.Choices) == 0 {
		return nil, errkit.New("ai provider returned no choices")
	}

	return []byte(stripCodeFence(response.Choices[0].Message.Content)), nil
}
