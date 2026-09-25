package http

import (
	"regexp"
	"slices"
)

var (
	// Determines if request condition are needed by detecting the pattern _xxx
	reRequestCondition = regexp.MustCompile(`(?m)_\d+`)
)

// NeedsRequestCondition determines if request condition should be enabled
func (request *Request) NeedsRequestCondition() bool {
	for _, matcher := range request.Matchers {
		if checkRequestConditionExpressions(matcher.DSL...) {
			return true
		}
		if checkRequestConditionExpressions(matcher.Part) {
			return true
		}
		// an llm matcher compares responses through inputs, which is where it
		// references {{body_1}} and friends
		if checkRequestConditionExpressions(matcher.Inputs...) {
			return true
		}
	}
	for _, extractor := range request.Extractors {
		if checkRequestConditionExpressions(extractor.DSL...) {
			return true
		}
		if checkRequestConditionExpressions(extractor.Part) {
			return true
		}
	}

	return false
}

func checkRequestConditionExpressions(expressions ...string) bool {
	return slices.ContainsFunc(expressions, reRequestCondition.MatchString)
}
