package expressions

import (
	"strings"

	"github.com/Knetic/govaluate"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
)

// Evaluate checks if the match contains a dynamic variable, for each
// found one we will check if it's an expression and can
// be compiled, it will be evaluated and the results will be returned.
//
// The provided keys from finalValues will be used as variable names
// for substitution inside the expression.
func Evaluate(data string, base map[string]interface{}) (string, error) {
	return evaluate(data, base)
}

// EvaluateByte checks if the match contains a dynamic variable, for each
// found one we will check if it's an expression and can
// be compiled, it will be evaluated and the results will be returned.
//
// The provided keys from finalValues will be used as variable names
// for substitution inside the expression.
func EvaluateByte(data []byte, base map[string]interface{}) ([]byte, error) {
	finalData, err := evaluate(string(data), base)
	return []byte(finalData), err
}

func evaluate(data string, base map[string]interface{}) (string, error) {
	data = replacer.Replace(data, base)

	dynamicValues := make(map[string]interface{})
	for _, match := range findMatches(data) {
		expr := generators.TrimDelimiters(match)

		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, dsl.HelperFunctions())
		if err != nil {
			continue
		}
		result, err := compiled.Evaluate(base)
		if err != nil {
			continue
		}
		dynamicValues[expr] = result
	}
	// Replacer dynamic values if any in raw request and parse  it
	return replacer.Replace(data, dynamicValues), nil
}

func findMatches(data string) []string {
	var matches []string
	for _, token := range strings.Split(data, marker.ParenthesisOpen) {
		closingToken := strings.LastIndex(token, marker.ParenthesisClose)
		if closingToken > 0 {
			matches = append(matches, token[:closingToken])
		}
	}
	return matches
}
