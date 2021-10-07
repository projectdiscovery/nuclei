package expressions

import (
	"errors"
	"regexp"
	"strings"
)

var unresolvedVariablesRegex = regexp.MustCompile(`(?:%7[B|b]|\{){2}([^}]+)(?:%7[D|d]|\}){2}["'\)\}]*`)

// ContainsUnresolvedVariables returns an error with variable names if the passed
// input contains unresolved {{<pattern-here>}} variables.
func ContainsUnresolvedVariables(data string) error {
	matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}
	errorString := &strings.Builder{}
	errorString.WriteString("unresolved variables found: ")

	for i, match := range matches {
		if len(match) < 2 {
			continue
		}
		errorString.WriteString(match[1])
		if i != len(matches)-1 {
			errorString.WriteString(",")
		}
	}
	errorMessage := errorString.String()
	return errors.New(errorMessage)
}

func ContainsVariablesWithNames(data string, names map[string]interface{}) error {
	matches := unresolvedVariablesRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}
	errorString := &strings.Builder{}
	errorString.WriteString("unresolved variables with values found: ")

	for i, match := range matches {
		if len(match) < 2 {
			continue
		}
		matchName := match[1]
		if _, ok := names[matchName]; !ok {
			errorString.WriteString(matchName)
			if i != len(matches)-1 {
				errorString.WriteString(",")
			}
		}
	}
	errorMessage := errorString.String()
	return errors.New(errorMessage)
}
