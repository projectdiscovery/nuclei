package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) bool {
	item, ok := getMatchPart(matcher.Part, data)
	if !ok {
		return false
	}

	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode.(int)))
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

// Extract performs extracting operation for a extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := getMatchPart(extractor.Part, data)
	if !ok {
		return nil
	}
	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(item)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
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

// responseToDSLMap converts a HTTP response to a map for use in DSL matching
func (r *Request) responseToDSLMap(resp *http.Response, host, matched, rawReq, rawResp, body, headers string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, len(extra)+8+len(resp.Header)+len(resp.Cookies()))
	for k, v := range extra {
		data[k] = v
	}

	data["host"] = host
	data["matched"] = matched
	data["request"] = rawReq
	data["response"] = rawResp
	data["content_length"] = resp.ContentLength
	data["status_code"] = resp.StatusCode
	data["body"] = body
	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(k))
		data[k] = strings.Join(v, " ")
	}
	data["all_headers"] = headers
	data["duration"] = duration.Seconds()
	data["template-id"] = r.options.TemplateID
	data["template-info"] = r.options.TemplateInfo
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
		Info:             wrapped.InternalEvent["template-info"].(map[string]interface{}),
		Type:             "http",
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
	}
	if r.options.Options.JSONOnlyRequests {
		data.Request = types.ToString(wrapped.InternalEvent["request"])
	} else if r.options.Options.JSONRequests {
		data.Request = types.ToString(wrapped.InternalEvent["request"])
		data.Response = types.ToString(wrapped.InternalEvent["response"])
	}
	return data
}
