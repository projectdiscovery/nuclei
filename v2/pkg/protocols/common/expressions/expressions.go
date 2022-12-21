package expressions

import (
	"fmt"
	"strings"

	"github.com/Knetic/govaluate"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	expMarkerParenthesis expressionMarker = expressionMarker{Open: marker.ParenthesisOpen, Close: marker.ParenthesisClose}
	expMarkerGeneral     expressionMarker = expressionMarker{Open: marker.General, Close: marker.General}
)

// maxIterations to avoid infinite loop
const maxIterations = 250

type expressionMarker struct {
	Open  string
	Close string
}

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
	var (
		iterations      int
		lastExpressions []string
	)
	hasExpression := true

	// expressions can be:
	// - simple: containing base values keys (variables)
	// - complex: containing helper functions [ + variables]
	// literals like {{2+2}} are not considered expressions
	for hasExpression {
		// breakout check #1 - check if we reached the maximum number of iterations
		if iterations > maxIterations {
			break
		}
		iterations++

		expressions := findExpressions(data, base, expMarkerParenthesis, expMarkerGeneral)

		// breakout check #2 - expressions are the same of last iteration
		if sliceutil.ElementsMatch(lastExpressions, expressions) {
			break
		}

		hasExpression = len(expressions) > 0
		for _, expression := range expressions {
			// turns expressions (either helper functions+base values or base values)
			var (
				retried  bool
				err      error
				compiled *govaluate.EvaluableExpression
			)
		expr_parse:
			compiled, err = govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions)
			if err != nil {
				// attempt to resolve it recursively
				if !retried {
					expression, err = evaluate(expression, base)
					if err == nil {
						continue
					}
					retried = true
					goto expr_parse
				}
				continue
			}
			result, err := compiled.Evaluate(base)
			if err != nil {
				continue
			}
			// replace incrementally
			data = replacer.ReplaceOne(data, expression, result)
			base[expression] = result
			base[fmt.Sprint(result)] = fmt.Sprint(result)
		}

		lastExpressions = expressions
	}
	return data, nil
}

func findExpressions(data string, base map[string]interface{}, markers ...expressionMarker) []string {
	var exps []string
	for _, marker := range markers {
		iterations := 0
		for {
			// check if we reached the maximum number of iterations
			if iterations > maxIterations {
				break
			}
			iterations++
			// attempt to find open markers
			indexOpenMarker := strings.Index(data, marker.Open)
			// exits if not found
			if indexOpenMarker < 0 {
				break
			}

			indexOpenMarkerOffset := indexOpenMarker + len(marker.Open)

			shouldSearchCloseMarker := true
			closeMarkerFound := false
			innerData := data
			var potentialMatch string
			var indexCloseMarker, indexCloseMarkerOffset int
			skip := indexOpenMarkerOffset
			for shouldSearchCloseMarker {
				// attempt to find close marker
				indexCloseMarker = stringsutil.IndexAt(innerData, marker.Close, skip)
				// if no close markers are found exit
				if indexCloseMarker < 0 {
					shouldSearchCloseMarker = false
					continue
				}
				indexCloseMarkerOffset = indexCloseMarker + len(marker.Close)

				potentialMatch = innerData[indexOpenMarkerOffset:indexCloseMarker]
				if isExpression(potentialMatch, base) {
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
	}
	return exps
}

func isExpression(data string, base map[string]interface{}) bool {
	if _, err := govaluate.NewEvaluableExpression(data); err == nil {
		return stringContainsAnyMapKey(data, base) || stringContainsAnyMapKey(data, dsl.HelperFunctions)
	}
	_, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions)
	return err == nil
}

func stringContainsAnyMapKey[T any](str string, maps ...map[string]T) bool {
	for _, m := range maps {
		for key := range m {
			if strings.Contains(str, key) {
				return true
			}
		}
	}
	return false
}
