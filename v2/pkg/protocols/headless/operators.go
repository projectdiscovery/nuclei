package headless

import (
	"strconv"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	itemStr, ok := request.getMatchPart(matcher.Part, data)
	if !ok && matcher.Type.MatcherType != matchers.DSLMatcher {
		return false, []string{}
	}

	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := getStatusCode(data)
		if !ok {
			return false, []string{}
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode)), []string{}
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), []string{}
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(itemStr))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	case matchers.XPathMatcher:
		return matcher.Result(matcher.MatchXPath(itemStr)), []string{}
	}
	return false, []string{}
}

func getStatusCode(data map[string]interface{}) (int, bool) {
	statusCodeValue, ok := data["status_code"]
	if !ok {
		return 0, false
	}
	statusCodeStr, ok := statusCodeValue.(string)
	if !ok {
		return 0, false
	}

	statusCode, err := strconv.Atoi(statusCodeStr)
	if err != nil {
		return 0, false
	}

	return statusCode, true
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	itemStr, ok := request.getMatchPart(extractor.Part, data)
	if !ok && !extractors.SupportsMap(extractor) {
		return nil
	}

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

func (request *Request) getMatchPart(part string, data output.InternalEvent) (string, bool) {
	switch part {
	case "body", "resp", "":
		part = "data"
	case "history":
		part = "history"
	case "header":
		part = "header"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	itemStr := types.ToString(item)

	return itemStr, true
}

// responseToDSLMap converts a headless response to a map for use in DSL matching
func (request *Request) responseToDSLMap(resp, headers, status_code, req, host, matched string, history string) output.InternalEvent {
	return output.InternalEvent{
		"host":          host,
		"matched":       matched,
		"req":           req,
		"data":          resp,
		"header":        headers,
		"status_code":   status_code,
		"history":       history,
		"type":          request.Type().String(),
		"template-id":   request.options.TemplateID,
		"template-info": request.options.TemplateInfo,
		"template-path": request.options.TemplatePath,
	}
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
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
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["data"]),
	}
	return data
}
