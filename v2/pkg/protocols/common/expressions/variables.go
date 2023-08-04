package expressions

import (
	"errors"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
)

var (
	numericalExpressionRegex = regexp.MustCompile(`^[0-9+\-/\W]+$`)
	unresolvedVariablesRegex = regexp.MustCompile(`(?:%7[B|b]|\{){2}([^}]+)(?:%7[D|d]|\}){2}["'\)\}]*`)
)

// ContainsUnresolvedVariables returns an error with variable names if the passed
// input contains unresolved {{<pattern-here>}} variables.
func ContainsUnresolvedVariables(items ...string) error {
	for _, data := range items {
		matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
		if len(matches) == 0 {
			return nil
		}
		var unresolvedVariables []string
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			// Skip if the match is an expression
			if numericalExpressionRegex.MatchString(match[1]) {
				continue
			}
			// or if it contains only literals (can be solved from expression engine)
			if hasLiteralsOnly(match[1]) {
				continue
			}
			unresolvedVariables = append(unresolvedVariables, match[1])
		}
		if len(unresolvedVariables) > 0 {
			return errors.New("unresolved variables found: " + strings.Join(unresolvedVariables, ","))
		}
	}

	return nil
}

// ContainsVariablesWithNames returns an error with variable names if the passed
// input contains unresolved {{<pattern-here>}} variables within the provided list
func ContainsVariablesWithNames(names map[string]interface{}, items ...string) error {
	for _, data := range items {
		matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
		if len(matches) == 0 {
			return nil
		}
		var unresolvedVariables []string
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			matchName := match[1]
			// Skip if the match is an expression
			if numericalExpressionRegex.MatchString(matchName) {
				continue
			}
			// or if it contains only literals (can be solved from expression engine)
			if hasLiteralsOnly(match[1]) {
				continue
			}
			if _, ok := names[matchName]; !ok {
				unresolvedVariables = append(unresolvedVariables, matchName)
			}
		}
		if len(unresolvedVariables) > 0 {
			return errors.New("unresolved variables with values found: " + strings.Join(unresolvedVariables, ","))
		}
	}

	return nil
}

// ContainsVariablesWithIgnoreList returns an error with variable names if the passed
// input contains unresolved {{<pattern-here>}} other than the ones listed in the ignore list
func ContainsVariablesWithIgnoreList(skipNames map[string]interface{}, items ...string) error {
	var unresolvedVariables []string
	for _, data := range items {
		matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
		if len(matches) == 0 {
			return nil
		}
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			matchName := match[1]
			// Skip if the match is an expression
			if numericalExpressionRegex.MatchString(matchName) {
				continue
			}
			// or if it contains only literals (can be solved from expression engine)
			if hasLiteralsOnly(match[1]) {
				continue
			}
			if _, ok := skipNames[matchName]; ok {
				continue
			}
			unresolvedVariables = append(unresolvedVariables, matchName)
		}
	}

	if len(unresolvedVariables) > 0 {
		return errors.New("unresolved variables with values found: " + strings.Join(unresolvedVariables, ","))
	}

	return nil
}

func hasLiteralsOnly(data string) bool {
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions)
	if err != nil {
		return false
	}
	if expr != nil {
		_, err = expr.Evaluate(nil)
		return err == nil
	}
	return true
}
