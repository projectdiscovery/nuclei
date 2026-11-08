package extractors

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubLLM struct {
	answer  string
	err     error
	lastGot string
}

func (s *stubLLM) Complete(_ context.Context, prompt string, _ bool) (string, error) {
	s.lastGot = prompt

	return s.answer, s.err
}

func llmExtractor(schema map[string]string) *Extractor {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: LLMExtractor}, Prompt: "extract", Schema: schema}
	return e
}

func TestExtractLLMReturnsSchemaValues(t *testing.T) {
	e := llmExtractor(map[string]string{"product": "string", "version": "string"})
	e.SetLLMClient(&stubLLM{answer: `{"product":"Jenkins","version":"2.4"}`})

	got := e.ExtractLLM("body", nil)
	require.Contains(t, got, "Jenkins")
	require.Contains(t, got, "2.4")
	require.Len(t, got, 2)
}

func TestExtractLLMSchemaReachesPromptInStableOrder(t *testing.T) {
	e := llmExtractor(map[string]string{"version": "string", "product": "string"})
	stub := &stubLLM{answer: `{}`}
	e.SetLLMClient(stub)

	e.ExtractLLM("body", nil)
	// both fields must be present, then product must come before version,
	// so an absent field (index -1) cannot make the order check pass falsely
	pi, vi := indexOf(stub.lastGot, "product"), indexOf(stub.lastGot, "version")
	require.NotEqual(t, -1, pi, "product field must reach the prompt")
	require.NotEqual(t, -1, vi, "version field must reach the prompt")
	require.Less(t, pi, vi, "schema fields must be in stable sorted order")
}

func TestExtractLLMFailClosed(t *testing.T) {
	cases := map[string]*Extractor{
		"nil client": llmExtractor(map[string]string{"x": "string"}),
		"error": func() *Extractor {
			e := llmExtractor(map[string]string{"x": "string"})
			e.SetLLMClient(&stubLLM{err: errors.New("boom")})
			return e
		}(),
		"unparsable": func() *Extractor {
			e := llmExtractor(map[string]string{"x": "string"})
			e.SetLLMClient(&stubLLM{answer: "not json"})
			return e
		}(),
	}
	for name, e := range cases {
		require.Empty(t, e.ExtractLLM("body", nil), name)
	}
}

func TestLLMExtractorRequiresSchema(t *testing.T) {
	e := llmExtractor(nil)
	require.ErrorContains(t, e.CompileExtractors(), "requires at least one schema")
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestExtractLLMInterpolatesPromptValues(t *testing.T) {
	e := &Extractor{Type: ExtractorTypeHolder{ExtractorType: LLMExtractor}, Prompt: "Extract the version of {{product}} from {{BaseURL}}.", Schema: map[string]string{"version": "string"}}
	stub := &stubLLM{answer: `{"version":"1.2.3"}`}
	e.SetLLMClient(stub)

	results := e.ExtractLLM("body", map[string]interface{}{"product": "nginx", "BaseURL": "https://acme.test"})
	require.Contains(t, results, "1.2.3")
	require.Contains(t, stub.lastGot, "Extract the version of nginx from https://acme.test.")
	require.NotContains(t, stub.lastGot, "{{product}}")
}
