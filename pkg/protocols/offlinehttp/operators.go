package offlinehttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := getMatchPart(matcher.Part, data)
	if !ok && matcher.Type.MatcherType != matchers.DSLMatcher {
		return false, []string{}
	}

	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := getStatusCode(data)
		if !ok {
			return false, []string{}
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode)), []string{responsehighlighter.CreateStatusCodeSnippet(data["response"].(string), statusCode)}
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item))), []string{}
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, nil))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(item))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(item))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	case matchers.XPathMatcher:
		return matcher.Result(matcher.MatchXPath(item)), []string{}
	}
	return false, []string{}
}

func getStatusCode(data map[string]interface{}) (int, bool) {
	statusCodeValue, ok := data["status_code"]
	if !ok {
		return 0, false
	}
	statusCode, ok := statusCodeValue.(int)
	if !ok {
		return 0, false
	}
	return statusCode, true
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := getMatchPart(extractor.Part, data)
	if !ok && !extractors.SupportsMap(extractor) {
		return nil
	}
	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(item)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

// getMatchPart returns the match part honoring "all" matchers + others.
func getMatchPart(part string, data output.InternalEvent) (string, bool) {
	if part == "header" {
		part = "all_headers"
	}
	var itemStr string

	if part == "all" {
		builder := &strings.Builder{}
		builder.WriteString(types.ToString(data["body"]))
		builder.WriteString(types.ToString(data["all_headers"]))
		itemStr = builder.String()
	} else {
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = types.ToString(item)
	}
	return itemStr, true
}

// responseToDSLMap converts an HTTP response to a map for use in DSL matching
func (request *Request) responseToDSLMap(resp *http.Response, host, matched, rawReq, rawResp, body, headers string, duration time.Duration, extra map[string]interface{}) output.InternalEvent {
	data := make(output.InternalEvent, 12+len(extra)+len(resp.Header)+len(resp.Cookies()))
	for k, v := range extra {
		data[k] = v
	}
	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(k))
		data[k] = strings.Join(v, " ")
	}

	data["path"] = host
	data["matched"] = matched
	data["request"] = rawReq
	data["response"] = rawResp
	data["status_code"] = resp.StatusCode
	data["body"] = body
	data["type"] = request.Type().String()
	data["all_headers"] = headers
	data["duration"] = duration.Seconds()
	data["template-id"] = request.options.TemplateID
	data["template-info"] = request.options.TemplateInfo
	data["template-path"] = request.options.TemplatePath
	data["content_length"] = utils.CalculateContentLength(resp.ContentLength, int64(len(body)))

	return data
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return request.compiledOperators
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		TemplateVerifier: request.options.TemplateVerifier,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Path:             types.ToString(wrapped.InternalEvent["path"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		MatcherStatus:    true,
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["raw"]),
		TemplateEncoded:  request.options.EncodeTemplate(),
		Error:            types.ToString(wrapped.InternalEvent["error"]),
	}
	return data
}
