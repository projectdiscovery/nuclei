package flow

import "github.com/projectdiscovery/nuclei/v3/pkg/operators"

// Checks if template has matchers
func hasMatchers(all []*operators.Operators) bool {
	for _, operator := range all {
		if len(operator.Matchers) > 0 {
			return true
		}
	}
	return false
}

// hasOperators checks if template has operators (i.e matchers/extractors)
func hasOperators(all []*operators.Operators) bool {
	for _, operator := range all {
		if operator != nil {
			return true
		}
	}
	return false
}
