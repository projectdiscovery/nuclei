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

func flatten(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		if len(v) == 1 {
			return v[0]
		}
		return v
	case []string:
		if len(v) == 1 {
			return v[0]
		}
		return v
	default:
		return v
	}
}
