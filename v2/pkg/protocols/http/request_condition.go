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
		for _, dslExpression := range matcher.DSL {
			if reRequestCondition.MatchString(dslExpression) {
				return true
			}
		}
	}
	for _, extractor := range request.Extractors {
		for _, dslExpression := range extractor.DSL {
			if reRequestCondition.MatchString(dslExpression) {
				return true
			}
		}
	}

	return false
}
