package expressions

import (
	"fmt"
	"slices"
	"strings"

	"github.com/projectdiscovery/govaluate"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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
	return evaluate(data, base, nil)
}

// EvaluateByte checks if the match contains a dynamic variable, for each
// found one we will check if it's an expression and can
// be compiled, it will be evaluated and the results will be returned.
//
// The provided keys from finalValues will be used as variable names
// for substitution inside the expression.
func EvaluateByte(data []byte, base map[string]interface{}) ([]byte, error) {
	finalData, err := evaluate(string(data), base, nil)
	return []byte(finalData), err
}

// EvaluateWithOptions renders expressions using the current scan's network policy.
func EvaluateWithOptions(data string, base map[string]interface{}, options *types.Options) (string, error) {
	return evaluate(data, base, options)
}

// evaluate renders data, the template text, with base, the data values.
//
// Expressions are located in data before anything is substituted, and each
// result is written at its expression's position. The text between
// expressions only has its placeholders replaced. Nothing that evaluate
// writes is scanned again, so a value or a helper result that looks like an
// expression stays literal and never takes another expression's result. On
// error, data is returned unchanged.
//
// Expressions can be simple (base keys) or complex (helper functions and base
// keys). Literals such as {{2+2}} are not expressions.
func evaluate(data string, base map[string]interface{}, options *types.Options) (string, error) {
	spans := findExpressionSpans(data, marker.ParenthesisOpen, marker.ParenthesisClose, base)
	if len(spans) == 0 {
		return replacer.Replace(data, base), nil
	}

	var (
		builder strings.Builder
		last    int
	)

	builder.Grow(len(data))

	for _, span := range spans {
		result, err := evaluateExpression(span.expression, base, options)
		if err != nil {
			return data, err
		}

		builder.WriteString(replacer.Replace(data[last:span.start], base))
		builder.WriteString(result)

		last = span.end
	}

	builder.WriteString(replacer.Replace(data[last:], base))

	return builder.String(), nil
}

// evaluateExpression compiles and evaluates one template-authored expression,
// the text between its markers, and returns the result as text.
func evaluateExpression(expression string, base map[string]any, options *types.Options) (string, error) {
	source := replaceStringPlaceholders(expression, base)

	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(source, dsl.HelperFunctions)
	if err != nil {
		return "", fmt.Errorf("failed to compile expression %q: %w", expression, err)
	}

	result, err := dsl.EvalWithOptions(compiled, base, options)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate expression %q: %w", expression, err)
	}

	// Preserve unresolved markers only when a helper call would otherwise
	// hide them from downstream validation. Plain expressions such as
	// comparisons should evaluate normally.
	if markers := unresolvedVarMarkers(compiled.Vars(), base); markers != "" {
		usesFunctions := slices.ContainsFunc(compiled.Tokens(), func(token govaluate.ExpressionToken) bool {
			return token.Kind == govaluate.FUNCTION
		})
		if usesFunctions && ContainsUnresolvedVariables(fmt.Sprint(result)) == nil {
			return markers, nil
		}
	}

	return types.ToString(result), nil
}

func replaceStringPlaceholders(expression string, base map[string]interface{}) string {
	if len(base) == 0 || (!strings.Contains(expression, marker.ParenthesisOpen) && !strings.Contains(expression, marker.General)) {
		return expression
	}

	var builder strings.Builder
	builder.Grow(len(expression))

	var quote byte
	escaped := false
	for i := 0; i < len(expression); {
		char := expression[i]

		if escaped {
			builder.WriteByte(char)
			escaped = false
			i++
			continue
		}

		if quote != 0 {
			if char == '\\' {
				builder.WriteByte(char)
				escaped = true
				i++
				continue
			}

			if char == quote {
				builder.WriteByte(char)
				quote = 0
				i++
				continue
			}

			replacement, next, ok := stringPlaceholderReplacement(expression, i, quote, base, marker.ParenthesisOpen, marker.ParenthesisClose)
			if ok {
				builder.WriteString(replacement)
				i = next
				continue
			}

			replacement, next, ok = stringPlaceholderReplacement(expression, i, quote, base, marker.General, marker.General)
			if ok {
				builder.WriteString(replacement)
				i = next
				continue
			}

			builder.WriteByte(char)
			i++
			continue
		}

		if char == '\'' || char == '"' {
			quote = char
		}

		builder.WriteByte(char)
		i++
	}

	return builder.String()
}

func stringPlaceholderReplacement(expression string, index int, quote byte, base map[string]interface{}, open, close string) (string, int, bool) {
	if !strings.HasPrefix(expression[index:], open) {
		return "", 0, false
	}

	markerStart := index + len(open)
	markerEnd := strings.Index(expression[markerStart:], close)
	if markerEnd < 0 {
		return "", 0, false
	}

	key := expression[markerStart : markerStart+markerEnd]
	value, ok := base[key]
	if !ok {
		return "", 0, false
	}

	replacement := EscapeStringValue(types.ToString(value), quote)
	next := markerStart + markerEnd + len(close)
	return replacement, next, true
}

// EscapeStringValue escapes value for insertion into a govaluate string literal
// that is already delimited by quote.
func EscapeStringValue(value string, quote byte) string {
	var builder strings.Builder
	builder.Grow(len(value))

	for i := 0; i < len(value); i++ {
		char := value[i]
		if char == '\\' || char == quote {
			builder.WriteByte('\\')
		}
		builder.WriteByte(char)
	}

	return builder.String()
}

// maxIterations to avoid infinite loop
const maxIterations = 250

// FindExpressions returns the expressions in data, the text between each
// matching OpenMarker and CloseMarker pair, in order.
func FindExpressions(data, OpenMarker, CloseMarker string, base map[string]interface{}) []string {
	spans := findExpressionSpans(data, OpenMarker, CloseMarker, base)
	if len(spans) == 0 {
		return nil
	}

	exps := make([]string, 0, len(spans))
	for _, span := range spans {
		exps = append(exps, span.expression)
	}

	return exps
}

// expressionSpan is one expression in template text: data[start:end] is the
// whole marker and expression is the text between its markers.
type expressionSpan struct {
	start, end int
	expression string
}

// findExpressionSpans finds the expressions in data and where each one sits.
// For each open marker, it takes the nearest close marker that makes the text
// between them an expression. When none does, the search resumes right after
// the open marker.
func findExpressionSpans(data, openMarker, closeMarker string, base map[string]any) []expressionSpan {
	var spans []expressionSpan

	for offset, iterations := 0, 0; iterations <= maxIterations; iterations++ {
		openIndex := strings.Index(data[offset:], openMarker)
		if openIndex < 0 {
			break
		}

		start := offset + openIndex
		inner := start + len(openMarker)
		offset = inner

		for search := inner; ; {
			closeIndex := stringsutil.IndexAt(data, closeMarker, search)
			if closeIndex < 0 {
				break
			}

			search = closeIndex + len(closeMarker)
			if expression := data[inner:closeIndex]; isExpression(expression, base) {
				spans = append(spans, expressionSpan{start: start, end: search, expression: expression})
				offset = search

				break
			}
		}
	}

	return spans
}

func isExpression(data string, base map[string]interface{}) bool {
	if _, ok := base[data]; ok {
		return false
	}

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
