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

	got := e.ExtractLLM("body")
	require.Contains(t, got, "Jenkins")
	require.Contains(t, got, "2.4")
	require.Len(t, got, 2)
}

func TestExtractLLMSchemaReachesPromptInStableOrder(t *testing.T) {
	e := llmExtractor(map[string]string{"version": "string", "product": "string"})
	stub := &stubLLM{answer: `{}`}
	e.SetLLMClient(stub)

	e.ExtractLLM("body")
	// sorted: product before version, regardless of map order
	require.Less(t, indexOf(stub.lastGot, "product"), indexOf(stub.lastGot, "version"))
}

func TestExtractLLMFailClosed(t *testing.T) {
	cases := map[string]*Extractor{
		"nil client":  llmExtractor(map[string]string{"x": "string"}),
		"error":       func() *Extractor { e := llmExtractor(map[string]string{"x": "string"}); e.SetLLMClient(&stubLLM{err: errors.New("boom")}); return e }(),
		"unparseable": func() *Extractor { e := llmExtractor(map[string]string{"x": "string"}); e.SetLLMClient(&stubLLM{answer: "not json"}); return e }(),
	}
	for name, e := range cases {
		require.Empty(t, e.ExtractLLM("body"), name)
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
