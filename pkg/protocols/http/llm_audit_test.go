package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestLLMAuditForResolvesByMatcherName(t *testing.T) {
	first := &matchers.LLMAudit{Verdict: "yes", Confidence: 0.9}
	second := &matchers.LLMAudit{Verdict: "no", Confidence: 0.2}
	data := map[string]interface{}{
		llmAuditKey: map[string]*matchers.LLMAudit{"stack-trace": first, "debug-page": second},
	}

	require.Same(t, first, llmAuditFor(data, "stack-trace"))
	require.Same(t, second, llmAuditFor(data, "debug-page"))
	// Ambiguous rather than wrong: with several audits and no name to go on,
	// attaching one of them would attribute a verdict to the wrong matcher.
	require.Nil(t, llmAuditFor(data, ""))
}

func TestLLMAuditForFallsBackToTheOnlyAudit(t *testing.T) {
	only := &matchers.LLMAudit{Verdict: "yes", Confidence: 0.9}
	data := map[string]interface{}{
		llmAuditKey: map[string]*matchers.LLMAudit{"": only},
	}

	require.Same(t, only, llmAuditFor(data, "unnamed-matcher"))
}

func TestLLMAuditForWithoutAudits(t *testing.T) {
	require.Nil(t, llmAuditFor(map[string]interface{}{}, "any"))
	require.Nil(t, llmAuditFor(map[string]interface{}{llmAuditKey: map[string]*matchers.LLMAudit{}}, "any"))
}

// Only findings the model produced carry the block; everything else stays as it
// was, so the field never appears on a pattern match.
func TestResultEventOmitsLLMWhenAbsent(t *testing.T) {
	event := &output.ResultEvent{TemplateID: "plain"}
	require.Nil(t, event.LLM)
}

func TestRecordLLMAuditIgnoresUnseededEvent(t *testing.T) {
	data := map[string]interface{}{}
	matcher := &matchers.Matcher{Name: "stack-trace"}

	require.NotPanics(t, func() {
		recordLLMAudit(data, matcher, &matchers.LLMAudit{Verdict: "yes"})
	})
	require.NotContains(t, data, llmAuditKey)
}
