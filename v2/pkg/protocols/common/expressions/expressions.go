package expressions

import (
	"strings"

	"github.com/Knetic/govaluate"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/stringsutil"
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
	// replace simple placeholders (key => value) MarkerOpen + key + MarkerClose and General + key + General to value
	data = replacer.Replace(data, base)

	// expressions can be:
	// - simple: containing base values keys (variables)
	// - complex: containing helper functions [ + variables]
	// literals like {{2+2}} are not considered expressions
	expressions := findExpressions(data, marker.ParenthesisOpen, marker.ParenthesisClose, mergeFunctions(dsl.HelperFunctions(), mapToFunctions(base)))
	dynamicValues := make(map[string]interface{})
	for _, expression := range expressions {
		// replace variable placeholders with base values
		expression = replacer.Replace(expression, base)
		// turns expressions (either helper functions+base values or base values)
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions())
		if err != nil {
			continue
		}
		result, err := compiled.Evaluate(base)
		if err != nil {
			continue
		}
		dynamicValues[expression] = result
	}
	// Replacer dynamic values if any in raw request and parse it
	return replacer.Replace(data, dynamicValues), nil
}

// maxIterations to avoid infinite loop
const maxIterations = 250

func findExpressions(data, OpenMarker, CloseMarker string, functions map[string]govaluate.ExpressionFunction) []string {
	var (
		iterations int
		exps       []string
	)
	for {
		// check if we reached the maximum number of iterations
		if iterations > maxIterations {
			break
		}
		iterations++
		// attempt to find open markers
		indexOpenMarker := strings.Index(data, OpenMarker)
		// exits if not found
		if indexOpenMarker < 0 {
			break
		}

		indexOpenMarkerOffset := indexOpenMarker + len(OpenMarker)

		shouldSearchCloseMarker := true
		closeMarkerFound := false
		innerData := data
		var potentialMatch string
		var indexCloseMarker, indexCloseMarkerOffset int
		skip := indexOpenMarkerOffset
		for shouldSearchCloseMarker {
			// attempt to find close marker
			indexCloseMarker = stringsutil.IndexAt(innerData, CloseMarker, skip)
			// if no close markers are found exit
			if indexCloseMarker < 0 {
				shouldSearchCloseMarker = false
				continue
			}
			indexCloseMarkerOffset = indexCloseMarker + len(CloseMarker)

			potentialMatch = innerData[indexOpenMarkerOffset:indexCloseMarker]
			if isExpression(potentialMatch, functions) {
				closeMarkerFound = true
				shouldSearchCloseMarker = false
				exps = append(exps, potentialMatch)
			} else {
				skip = indexCloseMarkerOffset
			}
		}

		if closeMarkerFound {
			// move after the close marker
			data = data[indexCloseMarkerOffset:]
		} else {
			// move after the open marker
			data = data[indexOpenMarkerOffset:]
		}
	}
	return exps
}

func isExpression(data string, functions map[string]govaluate.ExpressionFunction) bool {
	if _, err := govaluate.NewEvaluableExpression(data); err == nil {
		return stringsutil.ContainsAny(data, getFunctionsNames(functions)...)
	}

	// check if it's a complex expression
	_, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions())
	return err == nil
}

func mapToFunctions(vars map[string]interface{}) map[string]govaluate.ExpressionFunction {
	f := make(map[string]govaluate.ExpressionFunction)
	for k := range vars {
		f[k] = nil
	}
	return f
}

func mergeFunctions(m ...map[string]govaluate.ExpressionFunction) map[string]govaluate.ExpressionFunction {
	o := make(map[string]govaluate.ExpressionFunction)
	for _, mm := range m {
		for k, v := range mm {
			o[k] = v
		}
	}
	return o
}

func getFunctionsNames(m map[string]govaluate.ExpressionFunction) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
