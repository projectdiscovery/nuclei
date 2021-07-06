package network

import (
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) bool {
	partString := matcher.Part
	switch partString {
	case "body", "all", "":
		partString = "data"
	}

	item, ok := data[partString]
	if !ok {
		return false
	}
	itemStr := types.ToString(item)

	switch matcher.GetType() {
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr)))
	case matchers.WordsMatcher:
		return matcher.Result(matcher.MatchWords(itemStr))
	case matchers.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(itemStr))
	case matchers.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(itemStr))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data))
	}
	return false
}

// Extract performs extracting operation for a extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	partString := extractor.Part
	switch partString {
	case "body", "all", "":
		partString = "data"
	}

	item, ok := data[partString]
	if !ok {
		return nil
	}
	itemStr := types.ToString(item)

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

// responseToDSLMap converts a DNS response to a map for use in DSL matching
func (r *Request) responseToDSLMap(req, resp, raw, host, matched string) output.InternalEvent {
	data := make(output.InternalEvent, 6)

	// Some data regarding the request metadata
	data["host"] = host
	data["matched"] = matched
	data["request"] = req
	data["data"] = resp // Data is the last bytes read
	data["raw"] = raw   // Raw is the full transaction data for network
	data["template-id"] = r.options.TemplateID
	data["template-info"] = r.options.TemplateInfo
	data["template-path"] = r.options.TemplatePath
	return data
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 {
		return nil
	}
	results := make([]*output.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := r.makeResultEventItem(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := r.makeResultEventItem(wrapped)
			data.ExtractedResults = v
			data.ExtractorName = k
			results = append(results, data)
		}
	} else {
		data := r.makeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (r *Request) makeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(map[string]interface{}),
		Type:             "network",
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		Timestamp:        time.Now(),
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
	}
	if r.options.Options.JSONRequests {
		data.Request = types.ToString(wrapped.InternalEvent["request"])
		data.Response = types.ToString(wrapped.InternalEvent["data"])
	}
	return data
}
