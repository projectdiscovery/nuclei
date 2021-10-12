package dns

import (
	"bytes"
	"time"

	"github.com/miekg/dns"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	partString := matcher.Part
	switch partString {
	case "body", "all", "":
		partString = "raw"
	}

	item, ok := data[partString]
	if !ok {
		return false, []string{}
	}

	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := item.(int)
		if !ok {
			return false, []string{}
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode)), []string{}
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(types.ToString(item)))), []string{}
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(types.ToString(item), nil))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(types.ToString(item)))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(types.ToString(item)))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	}
	return false, []string{}
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	part := extractor.Part
	switch part {
	case "body", "all":
		part = "raw"
	}

	item, ok := data[part]
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
func (request *Request) responseToDSLMap(req, resp *dns.Msg, host, matched string) output.InternalEvent {
	return output.InternalEvent{
		"host":          host,
		"matched":       matched,
		"request":       req.String(),
		"rcode":         resp.Rcode,
		"question":      questionToString(resp.Question),
		"extra":         rrToString(resp.Extra),
		"answer":        rrToString(resp.Answer),
		"ns":            rrToString(resp.Ns),
		"raw":           resp.String(),
		"template-id":   request.options.TemplateID,
		"template-info": request.options.TemplateInfo,
		"template-path": request.options.TemplatePath,
	}
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		Type:             "dns",
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["raw"]),
	}
	return data
}

func rrToString(resourceRecords []dns.RR) string { // TODO rewrite with generics when available
	buffer := &bytes.Buffer{}
	for _, resourceRecord := range resourceRecords {
		buffer.WriteString(resourceRecord.String())
	}
	return buffer.String()
}

func questionToString(resourceRecords []dns.Question) string {
	buffer := &bytes.Buffer{}
	for _, resourceRecord := range resourceRecords {
		buffer.WriteString(resourceRecord.String())
	}
	return buffer.String()
}
