package matchers

import (
	"net/http"
	"strings"
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
			if !m.matchRegex(headers) {
				return false
			}
			return m.matchRegex(body)
		}
	}
	return false
}

// matchStatusCode matches a status code check against an HTTP Response
func (m *Matcher) matchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	for _, status := range m.Status {
		// Continue if the status codes don't match
		if statusCode != status {
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
	}
	return false
}

// matchStatusCode matches a size check against an HTTP Response
func (m *Matcher) matchSizeCode(length int) bool {
	// Iterate over all the sizes accepted as valid
	for _, size := range m.Size {
		// Continue if the size doesn't match
		if length != size {
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
	}
	return false
}

// matchWords matches a word check against an HTTP Response/Headers.
func (m *Matcher) matchWords(corpus string) bool {
	// Iterate over all the words accepted as valid
	for _, word := range m.Words {
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
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
	}
	return false
}

// matchRegex matches a regex check against an HTTP Response/Headers.
func (m *Matcher) matchRegex(corpus string) bool {
	// Iterate over all the regexes accepted as valid
	for _, regex := range m.regexCompiled {
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
	}
	return false
}
