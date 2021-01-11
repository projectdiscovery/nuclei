package dns

import (
	"bytes"

	"github.com/miekg/dns"
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
		partString = "raw"
	}

	item, ok := data[partString]
	if !ok {
		return false
	}
	itemStr := types.ToString(item)

	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := data["rcode"]
		if !ok {
			return false
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode.(int)))
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
	part, ok := data[extractor.Part]
	if !ok {
		return nil
	}
	partString := part.(string)

	switch partString {
	case "body", "all":
		partString = "raw"
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
func (r *Request) responseToDSLMap(req, resp *dns.Msg, host, matched string) output.InternalEvent {
	data := make(output.InternalEvent, 8)

	// Some data regarding the request metadata
	data["host"] = host
	data["matched"] = matched

	if r.options.Options.JSONRequests {
		data["request"] = req.String()
	}

	data["rcode"] = resp.Rcode
	buffer := &bytes.Buffer{}
	for _, question := range resp.Question {
		buffer.WriteString(question.String())
	}
	data["question"] = buffer.String()
	buffer.Reset()

	for _, extra := range resp.Extra {
		buffer.WriteString(extra.String())
	}
	data["extra"] = buffer.String()
	buffer.Reset()

	for _, answer := range resp.Answer {
		buffer.WriteString(answer.String())
	}
	data["answer"] = buffer.String()
	buffer.Reset()

	for _, ns := range resp.Ns {
		buffer.WriteString(ns.String())
	}
	data["ns"] = buffer.String()
	buffer.Reset()

	rawData := resp.String()
	data["raw"] = rawData
	return data
}

// makeResultEvent creates a result event from internal wrapped event
func (r *Request) makeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
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
		TemplateID:       r.options.TemplateID,
		Info:             r.options.TemplateInfo,
		Type:             "dns",
		Host:             wrapped.InternalEvent["host"].(string),
		Matched:          wrapped.InternalEvent["matched"].(string),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
	}
	if r.options.Options.JSONRequests {
		data.Request = wrapped.InternalEvent["request"].(string)
		data.Response = wrapped.InternalEvent["raw"].(string)
	}
	return data
}
