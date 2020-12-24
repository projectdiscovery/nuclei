package http

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
)

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) bool {
	part, ok := data[matcher.Part]
	if !ok {
		return false
	}
	partString := part.(string)

	switch partString {
	case "header":
		partString = "all_headers"
	case "all":
		partString = "raw"
	}
	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode.(int)))
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(partString)))
	case matchers.WordsMatcher:
		return matcher.Result(matcher.MatchWords(partString))
	case matchers.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(partString))
	case matchers.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(partString))
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
	case "header":
		partString = "all_headers"
	case "all":
		partString = "raw"
	}
	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(partString)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

// responseToDSLMap converts a HTTP response to a map for use in DSL matching
func responseToDSLMap(resp *http.Response, body, headers string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, len(extra)+6+len(resp.Header)+len(resp.Cookies()))
	for k, v := range extra {
		data[k] = v
	}

	data["content_length"] = resp.ContentLength
	data["status_code"] = resp.StatusCode

	data["body"] = body
	for _, cookie := range resp.Cookies() {
		data[cookie.Name] = cookie.Value
	}
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		data[k] = strings.Join(v, " ")
	}
	data["all_headers"] = headers

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		rawString := string(r)
		data["raw"] = rawString
	}
	data["duration"] = duration.Seconds()
	return data
}
