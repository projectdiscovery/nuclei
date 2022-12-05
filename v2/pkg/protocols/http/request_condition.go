package http

import (
	"regexp"
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
	for _, expression := range expressions {
		if reRequestCondition.MatchString(expression) {
			return true
		}
	}
	return false
}
