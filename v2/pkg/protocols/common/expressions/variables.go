package expressions

import (
	"errors"
	"regexp"
	"strings"
)

var unresolvedVariablesRegex = regexp.MustCompile(`(?:%7[B|b]|{){2}([^}]+)(?:%7[D|d]|}){2}["')}]*`)

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
