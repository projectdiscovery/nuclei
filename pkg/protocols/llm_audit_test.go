package protocols

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
		LLMAuditKey: map[string]*matchers.LLMAudit{"stack-trace": first, "debug-page": second},
	}

	require.Same(t, first, LLMAuditFor(data, "stack-trace"))
	require.Same(t, second, LLMAuditFor(data, "debug-page"))
	// Ambiguous rather than wrong: with several audits and no name to go on,
	// attaching one of them would attribute a verdict to the wrong matcher.
	require.Nil(t, LLMAuditFor(data, ""))
}

func TestLLMAuditForFallsBackToTheOnlyAudit(t *testing.T) {
	only := &matchers.LLMAudit{Verdict: "yes", Confidence: 0.9}
	data := map[string]interface{}{
		LLMAuditKey: map[string]*matchers.LLMAudit{"": only},
	}

	require.Same(t, only, LLMAuditFor(data, "unnamed-matcher"))
}

func TestLLMAuditForWithoutAudits(t *testing.T) {
	require.Nil(t, LLMAuditFor(map[string]interface{}{}, "any"))
	require.Nil(t, LLMAuditFor(map[string]interface{}{LLMAuditKey: map[string]*matchers.LLMAudit{}}, "any"))
}

// Only findings the model produced carry the block; everything else stays as it
// was, so the field never appears on a pattern match.
func TestResultEventOmitsLLMWhenAbsent(t *testing.T) {
	event := &output.ResultEvent{TemplateID: "plain"}
	require.Nil(t, event.LLM)
}

// Recording creates the map on first use as a fallback when Execute did not
// seed one. Prefer the Execute seed when dynamic extractors may MergeMaps.
func TestRecordLLMAuditCreatesTheMapOnFirstUse(t *testing.T) {
	data := map[string]interface{}{}
	matcher := &matchers.Matcher{Name: "stack-trace"}
	audit := &matchers.LLMAudit{Verdict: "yes"}

	RecordLLMAudit(data, matcher, audit)
	require.Same(t, audit, LLMAuditFor(data, "stack-trace"))

	require.NotPanics(t, func() {
		RecordLLMAudit(nil, matcher, audit)
	})
}

func TestAttachLLMAuditsReadsSeedSharedAcrossMerge(t *testing.T) {
	audit := &matchers.LLMAudit{Verdict: "yes"}
	event := map[string]interface{}{LLMAuditKey: make(map[string]*matchers.LLMAudit)}
	merged := make(map[string]interface{}, len(event)+1)
	for k, v := range event {
		merged[k] = v
	}
	merged["token"] = "from-extractor"

	RecordLLMAudit(merged, &matchers.Matcher{Name: "stack-trace"}, audit)
	results := AttachLLMAudits([]*output.ResultEvent{{MatcherName: "stack-trace"}}, event)
	require.Same(t, audit, results[0].LLM)
}
