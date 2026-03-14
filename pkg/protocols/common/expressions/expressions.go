package expressions

import (
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Eval compiles the given expression and evaluate it with the given values preserving the return type
func Eval(expression string, values map[string]interface{}) (interface{}, error) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions)
	if err != nil {
		return nil, err
	}
	return compiled.Evaluate(values)
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
	expressions := FindExpressions(data, marker.ParenthesisOpen, marker.ParenthesisClose, base)

	// replace simple placeholders (key => value) MarkerOpen + key + MarkerClose and General + key + General to value
	data = replacer.Replace(data, base)

	// expressions can be:
	// - simple: containing base values keys (variables)
	// - complex: containing helper functions [ + variables]
	// literals like {{2+2}} are not considered expressions
	for _, expression := range expressions {
		// replace variable placeholders with base values
		expression = replacer.Replace(expression, base)
		// turns expressions (either helper functions+base values or base values)
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.HelperFunctions)
		if err != nil {
			gologger.Warning().Msgf("Failed to compile expression '%s': %v", expression, err)
			continue
		}
		// propagate unresolved {{...}} markers from variable values so the
		// downstream ContainsUnresolvedVariables check can detect them instead
		// of having encoding functions (e.g. base64) hide them
		if markers := unresolvedVarMarkers(compiled.Vars(), base); markers != "" {
			data = replacer.ReplaceOne(data, expression, markers)
			continue
		}
		result, err := compiled.Evaluate(base)
		if err != nil {
			gologger.Warning().Msgf("Failed to evaluate expression '%s': %v", expression, err)
			continue
		}
		// replace incrementally
		data = replacer.ReplaceOne(data, expression, result)
	}
	return data, nil
}

// maxIterations to avoid infinite loop
const maxIterations = 250

func FindExpressions(data, OpenMarker, CloseMarker string, base map[string]interface{}) []string {
	var (
		iterations int
		exps       []string
	)
	for iterations <= maxIterations {
		// check if we reached the maximum number of iterations

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
	return exps
}

func isExpression(data string, base map[string]interface{}) bool {
	if _, err := govaluate.NewEvaluableExpression(data); err == nil {
		if stringsutil.ContainsAny(data, getFunctionsNames(base)...) {
			return true
		} else if stringsutil.ContainsAny(data, dsl.FunctionNames...) {
			return true
		}
		return false
	}
	_, err := govaluate.NewEvaluableExpressionWithFunctions(data, dsl.HelperFunctions)
	return err == nil
}

// unresolvedVarMarkers returns concatenated {{...}} markers found in the
// string values of the given variable names. Returns "" if none.
func unresolvedVarMarkers(vars []string, base map[string]any) string {
	seen := make(map[string]struct{})
	var markers []string
	for _, varName := range vars {
		val, ok := base[varName]
		if !ok {
			continue
		}
		valStr, ok := val.(string)
		if !ok {
			continue
		}
		for _, match := range unresolvedVariablesRegex.FindAllStringSubmatch(valStr, -1) {
			if len(match) < 2 {
				continue
			}
			if numericalExpressionRegex.MatchString(match[1]) || hasLiteralsOnly(match[1]) {
				continue
			}
			full := marker.ParenthesisOpen + match[1] + marker.ParenthesisClose
			if _, exists := seen[full]; !exists {
				seen[full] = struct{}{}
				markers = append(markers, full)
			}
		}
	}
	return strings.Join(markers, "")
}

func getFunctionsNames(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
