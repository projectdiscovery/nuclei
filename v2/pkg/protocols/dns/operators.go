package dns

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryabledns"
)

// Match matches a generic data response against a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := request.getMatchPart(matcher.Part, data)
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
	item, ok := request.getMatchPart(extractor.Part, data)
	if !ok {
		return nil
	}

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(types.ToString(item))
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

func (request *Request) getMatchPart(part string, data output.InternalEvent) (interface{}, bool) {
	switch part {
	case "body", "all", "":
		part = "raw"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}

	return item, true
}

// responseToDSLMap converts a DNS response to a map for use in DSL matching
func (request *Request) responseToDSLMap(reqString, respString string, resp *dns.Msg, host, matched string, traceData *retryabledns.TraceData) output.InternalEvent {
	return output.InternalEvent{
		"host":          host,
		"matched":       matched,
		"request":       reqString,
		"rcode":         resp.Rcode,
		"question":      questionToString(resp.Question),
		"extra":         rrToString(resp.Extra),
		"answer":        rrToString(resp.Answer),
		"ns":            rrToString(resp.Ns),
		"raw":           respString,
		"template-id":   request.options.TemplateID,
		"template-info": request.options.TemplateInfo,
		"template-path": request.options.TemplatePath,
		"type":          request.Type().String(),
		"trace":         traceToString(traceData, false),
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
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		MatcherStatus:    true,
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

func traceToString(traceData *retryabledns.TraceData, withSteps bool) string {
	buffer := &bytes.Buffer{}
	if traceData != nil {
		for i, dnsRecord := range traceData.DNSData {
			if withSteps {
				buffer.WriteString(fmt.Sprintf("request %d to resolver %s:\n", i, strings.Join(dnsRecord.Resolver, ",")))
			}
			buffer.WriteString(dnsRecord.Raw)
		}
	}
	return buffer.String()
}
