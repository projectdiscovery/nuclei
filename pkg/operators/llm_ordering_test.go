package operators

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

// counting stubs stand in for the protocol's match/extract funcs so the tests
// can assert how often the expensive operator was reached, not just the result.
type opCounter struct {
	llmMatches   int
	cheapMatches int
	llmExtracts  int
}

func (c *opCounter) matchFunc(cheap, llm bool) MatchFunc {
	return func(_ map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
		if matcher.GetType() == matchers.LLMMatcher {
			c.llmMatches++
			return llm, []string{"llm"}
		}
		c.cheapMatches++
		return cheap, []string{"cheap"}
	}
}

func (c *opCounter) extractFunc() ExtractFunc {
	return func(_ map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
		if extractor.GetType() == extractors.LLMExtractor {
			c.llmExtracts++
		}
		return map[string]struct{}{"value": {}}
	}
}

func cheapMatcher(name string) *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher}, Name: name}
}

func llmMatcher(name string) *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher}, Name: name}
}

func TestExecuteSkipsLLMWhenCheapANDMatcherFails(t *testing.T) {
	counter := &opCounter{}
	// llm written first, exactly the order an author should not have to avoid
	ops := &Operators{Matchers: []*matchers.Matcher{llmMatcher("llm"), cheapMatcher("status")}}
	ops.matchersCondition = matchers.ANDCondition

	_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(false, true), counter.extractFunc(), false)
	require.False(t, ok)
	require.Equal(t, 0, counter.llmMatches, "a failing cheap matcher decides an AND, so the model must not be called")
}

func TestExecuteSkipsLLMWhenCheapORMatcherAlreadyMatched(t *testing.T) {
	counter := &opCounter{}
	ops := &Operators{Matchers: []*matchers.Matcher{llmMatcher("llm"), cheapMatcher("status")}}
	ops.matchersCondition = matchers.ORCondition

	_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(true, true), counter.extractFunc(), false)
	require.True(t, ok)
	require.Equal(t, 0, counter.llmMatches, "the outcome is already decided under OR")
}

func TestExecuteRunsLLMWhenCheapMatchersLeaveItUndecided(t *testing.T) {
	counter := &opCounter{}
	ops := &Operators{Matchers: []*matchers.Matcher{cheapMatcher("status"), llmMatcher("llm")}}
	ops.matchersCondition = matchers.ORCondition

	_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(false, true), counter.extractFunc(), false)
	require.True(t, ok)
	require.Equal(t, 1, counter.llmMatches)
}

func TestExecuteRunsLLMWhenCheapANDMatchersPass(t *testing.T) {
	counter := &opCounter{}
	ops := &Operators{Matchers: []*matchers.Matcher{llmMatcher("llm"), cheapMatcher("status")}}
	ops.matchersCondition = matchers.ANDCondition

	_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(true, true), counter.extractFunc(), false)
	require.True(t, ok)
	require.Equal(t, 1, counter.llmMatches)
}

// Reordering must not renumber the matchers, or unnamed ones silently change
// the names they report in output.
func TestExecutePreservesUnnamedMatcherIndexes(t *testing.T) {
	counter := &opCounter{}
	first := llmMatcher("")
	second := cheapMatcher("")
	ops := &Operators{Matchers: []*matchers.Matcher{first, second}}
	ops.matchersCondition = matchers.ORCondition

	result, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(false, true), counter.extractFunc(), true)
	require.True(t, ok)
	require.Contains(t, result.Matches, "llm-1", "the llm matcher keeps index 1 despite running second")
}

func TestExecuteDefersLLMExtractorUntilMatched(t *testing.T) {
	llmExtractor := &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.LLMExtractor}, Name: "version",
	}

	t.Run("no match", func(t *testing.T) {
		counter := &opCounter{}
		ops := &Operators{Matchers: []*matchers.Matcher{cheapMatcher("status")}, Extractors: []*extractors.Extractor{llmExtractor}}

		_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(false, false), counter.extractFunc(), false)
		require.False(t, ok)
		require.Equal(t, 0, counter.llmExtracts, "a 404 must not cost a model round trip")
	})

	t.Run("matched", func(t *testing.T) {
		counter := &opCounter{}
		ops := &Operators{Matchers: []*matchers.Matcher{cheapMatcher("status")}, Extractors: []*extractors.Extractor{llmExtractor}}

		_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(true, true), counter.extractFunc(), false)
		require.True(t, ok)
		require.Equal(t, 1, counter.llmExtracts)
	})
}

func TestExecuteRunsLLMExtractorWhenTemplateHasNoMatchers(t *testing.T) {
	counter := &opCounter{}
	ops := &Operators{Extractors: []*extractors.Extractor{
		{Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.LLMExtractor}, Name: "version"},
	}}

	_, ok := ops.Execute(map[string]interface{}{}, counter.matchFunc(false, false), counter.extractFunc(), false)
	require.True(t, ok)
	require.Equal(t, 1, counter.llmExtracts, "extraction is the point when there are no matchers")
}
