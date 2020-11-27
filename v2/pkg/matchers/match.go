package matchers

import (
	"net/http"
	"strings"
	"time"

	"github.com/Mzack9999/dsl"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
)

// Match matches a http response again a given matcher
func (m *Matcher) Match(resp *http.Response, body, headers string, duration time.Duration, data map[string]interface{}) bool {
	switch m.matcherType {
	case StatusMatcher:
		return m.matchStatusCode(resp.StatusCode)
	case SizeMatcher:
		return m.matchSize(len(body))
	case WordsMatcher:
		// Match the parts as required for word check
		if m.part == BodyPart {
			return m.matchWords(body)
		} else if m.part == HeaderPart {
			return m.matchWords(headers)
		} else {
			return m.matchWords(headers + body)
		}
	case RegexMatcher:
		// Match the parts as required for regex check
		if m.part == BodyPart {
			return m.matchRegex(body)
		} else if m.part == HeaderPart {
			return m.matchRegex(headers)
		} else {
			return m.matchRegex(headers + body)
		}
	case BinaryMatcher:
		// Match the parts as required for binary characters check
		if m.part == BodyPart {
			return m.matchBinary(body)
		} else if m.part == HeaderPart {
			return m.matchBinary(headers)
		} else {
			return m.matchBinary(headers + body)
		}
	case DSLMatcher:
		// Match complex query
		return m.matchDSL(generators.MergeMaps(HTTPToMap(resp, body, headers, duration, ""), data))
	}

	return false
}

// MatchDNS matches a dns response against a given matcher
func (m *Matcher) MatchDNS(msg *dns.Msg) bool {
	switch m.matcherType {
	// [WIP] add dns status code matcher
	case SizeMatcher:
		return m.matchSize(msg.Len())
	case WordsMatcher:
		// Match for word check
		return m.matchWords(msg.String())
	case RegexMatcher:
		// Match regex check
		return m.matchRegex(msg.String())
	case BinaryMatcher:
		// Match binary characters check
		return m.matchBinary(msg.String())
	case DSLMatcher:
		// Match complex query
		return m.matchDSL(DNSToMap(msg, ""))
	}

	return false
}

// matchStatusCode matches a status code check against an HTTP Response
func (m *Matcher) matchStatusCode(statusCode int) bool {
	data := make(map[string]interface{})
	data["status_code"] = statusCode
	data["statuses"] = m.Status
	expr := m.negative + "equals_any(status_code, statuses)"
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}

// matchSize matches a size check against an HTTP Response
func (m *Matcher) matchSize(size int) bool {
	data := make(map[string]interface{})
	data["size"] = size
	data["sizes"] = m.Size
	expr := m.negative + "equals_any(size, sizes)"
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchWords(corpus string) bool {
	data := make(map[string]interface{})
	data["corpus"] = corpus
	data["words"] = m.Words
	expr := m.negative + "contains_any(corpus, words)"
	if m.condition == ANDCondition {
		expr = m.negative + "contains_all(corpus, words)"
	}
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}

// matchRegex matches a regex check against an HTTP Response/Headers.
func (m *Matcher) matchRegex(corpus string) bool {
	data := make(map[string]interface{})
	data["corpus"] = corpus
	data["regexes"] = m.Words
	expr := m.negative + "regex_any(corpus, regexes)"
	if m.condition == ANDCondition {
		expr = m.negative + "regex_all(corpus, words)"
	}
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchBinary(corpus string) bool {
	data := make(map[string]interface{})
	data["corpus"] = corpus
	data["binaries"] = m.Words
	expr := m.negative + "contains_any(corpus, binaries)"
	if m.condition == ANDCondition {
		expr = m.negative + "contains_all(corpus, binaries)"
	}
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}

// matchDSL matches on a generic map result
func (m *Matcher) matchDSL(data map[string]interface{}) bool {
	joinOperator := "||"
	if m.condition == ANDCondition {
		joinOperator = "&&"
	}
	expr := m.negative + strings.Join(m.DSL, joinOperator)
	v, err := dsl.EvalExpr(expr, data)
	return v.(bool) && err == nil
}
