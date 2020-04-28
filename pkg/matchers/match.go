package matchers

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// Match matches a http response again a given matcher
func (m *Matcher) Match(resp *http.Response, body, headers string) bool {
	switch m.matcherType {
	case StatusMatcher:
		return m.matchStatusCode(resp.StatusCode)
	case SizeMatcher:
		return m.matchSizeCode(len(body))
	case WordsMatcher:
		// Match the parts as required for word check
		if m.part == BodyPart {
			return m.matchWords(body)
		} else if m.part == HeaderPart {
			return m.matchWords(headers)
		} else {
			if !m.matchWords(headers) {
				return false
			}
			return m.matchWords(body)
		}
	case RegexMatcher:
		// Match the parts as required for regex check
		if m.part == BodyPart {
			return m.matchRegex(body)
		} else if m.part == HeaderPart {
			return m.matchRegex(headers)
		} else {
			if m.matchRegex(headers) {
				return true
			}
			return m.matchRegex(body)
		}
	case BinaryMatcher:
		// Match the parts as required for binary characters check
		if m.part == BodyPart {
			return m.matchBinary(body)
		} else if m.part == HeaderPart {
			return m.matchBinary(headers)
		} else {
			if !m.matchBinary(headers) {
				return false
			}
			return m.matchBinary(body)
		}
	case DSLMatcher:
		// Match complex query
		return m.matchDSL(httpToMap(resp, body, headers))
	}
	return false
}

// MatchDNS matches a dns response against a given matcher
func (m *Matcher) MatchDNS(msg *dns.Msg) bool {
	switch m.matcherType {
	// [WIP] add dns status code matcher
	case SizeMatcher:
		return m.matchSizeCode(msg.Len())
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
		return m.matchDSL(dnsToMap(msg))
	}
	return false
}

// matchStatusCode matches a status code check against an HTTP Response
func (m *Matcher) matchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range m.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchStatusCode matches a size check against an HTTP Response
func (m *Matcher) matchSizeCode(length int) bool {
	// Iterate over all the sizes accepted as valid
	//
	// Sizes codes don't support AND conditions.
	for _, size := range m.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchWords(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, word := range m.Words {
		// Continue if the word doesn't match
		if strings.Index(corpus, word) == -1 {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Words)-1 == i {
			return true
		}
	}
	return false
}

// matchRegex matches a regex check against an HTTP Response/Headers.
func (m *Matcher) matchRegex(corpus string) bool {
	// Iterate over all the regexes accepted as valid
	for i, regex := range m.regexCompiled {
		// Continue if the regex doesn't match
		if !regex.MatchString(corpus) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the regex, return with true
		if len(m.regexCompiled)-1 == i {
			return true
		}
	}
	return false
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchBinary(corpus string) bool {

	// Iterate over all the words accepted as valid
	for i, binary := range m.Binary {
		// Continue if the word doesn't match

		hexa, _ := hex.DecodeString(binary)
		if !strings.Contains(corpus, string(hexa)) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Binary)-1 == i {
			return true
		}
	}
	return false
}

// matchDSL matches on a generic map result
func (m *Matcher) matchDSL(mp map[string]interface{}) bool {
	// Iterate over all the regexes accepted as valid
	for i, expression := range m.dslCompiled {
		result, err := expression.Evaluate(mp)
		if err != nil {
			continue
		}
		var bResult bool
		bResult, ok := result.(bool)

		// Continue if the regex doesn't match
		if !ok || !bResult {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the dsl, return with true
		if len(m.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}
