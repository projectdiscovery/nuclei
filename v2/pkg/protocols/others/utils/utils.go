package utils

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// MakeResultEventItemFunc returns a result event for an internal wrapped event item
type MakeResultEventItemFunc func(wrapped *output.InternalWrappedEvent) *output.ResultEvent

// MakeResultEvent creates a result event from internal wrapped event
func MakeResultEvent(wrapped *output.InternalWrappedEvent, makeEventItemFunc MakeResultEventItemFunc) []*output.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 {
		return nil
	}
	results := make([]*output.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := makeEventItemFunc(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := makeEventItemFunc(wrapped)
			data.ExtractedResults = v
			data.ExtractorName = k
			results = append(results, data)
		}
	} else {
		data := makeEventItemFunc(wrapped)
		results = append(results, data)
	}
	return results
}

// ExtractFunc performs extracting operation for an extractor on model and returns true or false.
func ExtractFunc(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := data[extractor.Part]
	if !ok {
		return nil
	}
	itemStr := types.ToString(item)

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.JSONExtractor:
		return extractor.ExtractJSON(itemStr)
	case extractors.XPathExtractor:
		return extractor.ExtractHTML(itemStr)
	}
	return nil
}

// MatchFunc performs matching operation for a matcher on model and returns true or false.
func MatchFunc(data map[string]interface{}, matcher *matchers.Matcher) bool {
	partItem, ok := data[matcher.Part]
	if !ok && len(matcher.DSL) == 0 {
		return false
	}
	item := types.ToString(partItem)

	switch matcher.GetType() {
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item)))
	case matchers.WordsMatcher:
		return matcher.Result(matcher.MatchWords(item))
	case matchers.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(item))
	case matchers.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(item))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data))
	}
	return false
}
