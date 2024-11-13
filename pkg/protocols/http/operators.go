package http

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
// TODO: Try to consolidate this in protocols.MakeDefaultMatchFunc to avoid any inconsistencies
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := request.getMatchPart(matcher.Part, data)
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
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, data))
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
	item, ok := request.getMatchPart(extractor.Part, data)
	if !ok && !extractors.SupportsMap(extractor) {
		return nil
	}
	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(item)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.XPathExtractor:
		return extractor.ExtractXPath(item)
	case extractors.JSONExtractor:
		return extractor.ExtractJSON(item)
	case extractors.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

// getMatchPart returns the match part honoring "all" matchers + others.
func (request *Request) getMatchPart(part string, data output.InternalEvent) (string, bool) {
	if part == "" {
		part = "body"
	}
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
		request.setHashOrDefault(data, strings.ToLower(cookie.Name), cookie.Value)
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		request.setHashOrDefault(data, k, strings.Join(v, " "))
	}
	data["host"] = host
	data["type"] = request.Type().String()
	data["matched"] = matched
	request.setHashOrDefault(data, "request", rawReq)
	request.setHashOrDefault(data, "response", rawResp)
	data["status_code"] = resp.StatusCode
	request.setHashOrDefault(data, "body", body)
	request.setHashOrDefault(data, "all_headers", headers)
	request.setHashOrDefault(data, "header", headers)
	data["duration"] = duration.Seconds()
	data["template-id"] = request.options.TemplateID
	data["template-info"] = request.options.TemplateInfo
	data["template-path"] = request.options.TemplatePath

	data["content_length"] = utils.CalculateContentLength(resp.ContentLength, int64(len(body)))

	if request.StopAtFirstMatch || request.options.StopAtFirstMatch {
		data["stop-at-first-match"] = true
	}
	return data
}

// TODO: disabling hdd storage while testing backpressure mechanism
func (request *Request) setHashOrDefault(data output.InternalEvent, k string, v string) {
	// if hash, err := request.options.Storage.SetString(v); err == nil {
	// 	data[k] = hash
	// } else {
	data[k] = v
	//}
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	fields := utils.GetJsonFieldsFromURL(types.ToString(wrapped.InternalEvent["host"]))
	if types.ToString(wrapped.InternalEvent["ip"]) != "" {
		fields.Ip = types.ToString(wrapped.InternalEvent["ip"])
	}
	if types.ToString(wrapped.InternalEvent["path"]) != "" {
		fields.Path = types.ToString(wrapped.InternalEvent["path"])
	}
	var isGlobalMatchers bool
	if value, ok := wrapped.InternalEvent["global-matchers"]; ok {
		isGlobalMatchers = value.(bool)
	}
	var analyzerDetails string
	if value, ok := wrapped.InternalEvent["analyzer_details"]; ok {
		analyzerDetails = value.(string)
	}
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		TemplateVerifier: request.options.TemplateVerifier,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             fields.Host,
		Port:             fields.Port,
		Scheme:           fields.Scheme,
		URL:              fields.URL,
		Path:             fields.Path,
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		IP:               fields.Ip,
		GlobalMatchers:   isGlobalMatchers,
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         request.truncateResponse(wrapped.InternalEvent["response"]),
		CURLCommand:      types.ToString(wrapped.InternalEvent["curl-command"]),
		TemplateEncoded:  request.options.EncodeTemplate(),
		Error:            types.ToString(wrapped.InternalEvent["error"]),
		AnalyzerDetails:  analyzerDetails,
	}
	return data
}

func (request *Request) truncateResponse(response interface{}) string {
	responseString := types.ToString(response)
	if len(responseString) > request.options.Options.ResponseSaveSize {
		return responseString[:request.options.Options.ResponseSaveSize]
	}
	return responseString
}
