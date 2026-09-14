package matchers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubLLM struct {
	answer  string
	err     error
	calls   int
	lastGot string
}

func (s *stubLLM) Complete(_ context.Context, prompt string, _ bool) (string, error) {
	s.calls++
	s.lastGot = prompt

	return s.answer, s.err
}

func llmMatcher(prompt string) *Matcher {
	return &Matcher{Type: MatcherTypeHolder{MatcherType: LLMMatcher}, Prompt: prompt}
}

func TestMatchLLMFiresOnExpectedVerdictAboveConfidence(t *testing.T) {
	m := llmMatcher("admin login form?")
	m.MinConfidence = 0.8
	m.SetLLMClient(&stubLLM{answer: `{"verdict":"yes","confidence":0.94,"evidence":"login form posting to /admin"}`})

	ok, snips := m.MatchLLM("<form ...>")
	require.True(t, ok)
	require.Equal(t, []string{"login form posting to /admin"}, snips)
}

func TestMatchLLMDoesNotFireBelowConfidence(t *testing.T) {
	m := llmMatcher("admin login form?")
	m.MinConfidence = 0.8
	m.SetLLMClient(&stubLLM{answer: `{"verdict":"yes","confidence":0.3}`})

	ok, _ := m.MatchLLM("x")
	require.False(t, ok, "verdict below the confidence threshold must not match")
}

func TestMatchLLMDoesNotFireOnWrongVerdict(t *testing.T) {
	m := llmMatcher("q")
	m.SetLLMClient(&stubLLM{answer: `{"verdict":"no","confidence":0.99}`})

	ok, _ := m.MatchLLM("x")
	require.False(t, ok)
}

func TestMatchLLMCustomExpectAndOptions(t *testing.T) {
	m := llmMatcher("real credential or example?")
	m.Expect = "real"
	m.Options = []string{"real", "example"}
	stub := &stubLLM{answer: `{"verdict":"real","confidence":1}`}
	m.SetLLMClient(stub)

	ok, _ := m.MatchLLM("AKIA...")
	require.True(t, ok)
	require.Contains(t, stub.lastGot, "real, example", "allowed verdicts must reach the prompt")
}

// The guardrail: any failure resolves to "no match", never an error-match.
func TestMatchLLMFailClosed(t *testing.T) {
	cases := map[string]*Matcher{
		"nil client":     llmMatcher("q"),
		"provider error": func() *Matcher { m := llmMatcher("q"); m.SetLLMClient(&stubLLM{err: errors.New("boom")}); return m }(),
		"unparsable":     func() *Matcher { m := llmMatcher("q"); m.SetLLMClient(&stubLLM{answer: "not json"}); return m }(),
		"empty answer":   func() *Matcher { m := llmMatcher("q"); m.SetLLMClient(&stubLLM{answer: ""}); return m }(),
	}
	for name, m := range cases {
		ok, _ := m.MatchLLM("x")
		require.False(t, ok, name)
	}
}

func TestMatchLLMDefaultsExpectToYes(t *testing.T) {
	m := llmMatcher("q") // no Expect set
	m.SetLLMClient(&stubLLM{answer: `{"verdict":"YES","confidence":0.5}`})

	ok, _ := m.MatchLLM("x")
	require.True(t, ok, "expect defaults to yes and match is case-insensitive")
}

func TestMatchLLMTruncatesInput(t *testing.T) {
	m := llmMatcher("q")
	m.MaxInputTokens = 1 // ~4 chars
	stub := &stubLLM{answer: `{"verdict":"yes","confidence":1}`}
	m.SetLLMClient(stub)

	_, _ = m.MatchLLM("abcdefghijklmnop")
	require.NotContains(t, stub.lastGot, "efghijklmnop", "input beyond the token cap must be dropped")
}

// A model that omits confidence unmarshals to 0. With a 0 floor that counted as
// a match, so an answer carrying no confidence at all produced findings.
func TestMatchLLMRejectsVerdictWithoutConfidence(t *testing.T) {
	m := llmMatcher("admin login form?")
	m.SetLLMClient(&stubLLM{answer: `{"verdict":"yes"}`})

	ok, _ := m.MatchLLM("<form ...>")
	require.False(t, ok)
}

func TestMatchLLMRejectsConfidenceOutsideContract(t *testing.T) {
	for _, answer := range []string{
		`{"verdict":"yes","confidence":95}`,
		`{"verdict":"yes","confidence":-1}`,
	} {
		m := llmMatcher("admin login form?")
		m.SetLLMClient(&stubLLM{answer: answer})

		ok, _ := m.MatchLLM("<form ...>")
		require.False(t, ok, answer)
	}
}

func TestMatchLLMFailsClosedWithoutClient(t *testing.T) {
	m := llmMatcher("admin login form?")

	ok, _ := m.MatchLLM("<form ...>")
	require.False(t, ok)
}

// Negating a matcher whose every failure path reports "no match" would turn an
// unreachable provider into a finding on every target.
func TestValidateLLMRejectsNegative(t *testing.T) {
	m := llmMatcher("admin login form?")
	m.Negative = true

	require.ErrorContains(t, m.validateLLM(), "cannot be negative")
}

func TestValidateLLMRejectsConfidenceOutOfRange(t *testing.T) {
	for _, confidence := range []float64{-0.1, 1.1} {
		m := llmMatcher("admin login form?")
		m.MinConfidence = confidence

		require.ErrorContains(t, m.validateLLM(), "between 0 and 1", confidence)
	}
}

func TestValidateLLMAcceptsBounds(t *testing.T) {
	for _, confidence := range []float64{0, 0.5, 1} {
		m := llmMatcher("admin login form?")
		m.MinConfidence = confidence

		require.NoError(t, m.validateLLM(), confidence)
	}
}
