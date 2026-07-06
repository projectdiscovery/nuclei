package matchers

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
)

var dslStringMarkerRegex = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

// dslStringMarker represents a span of an unresolved DSL expression within a
// string literal.
type dslStringMarker struct {
	start int
	end   int
	expr  string
	quote byte
}

type textSpan struct {
	start int
	end   int
}

type stringLiteralSpan struct {
	start int
	end   int
	quote byte
}

func resolveDSLStringMarkers(expression string, data map[string]interface{}) (string, error) {
	// Resolve only marker spans already present in the compiled DSL source.
	// Values are escaped for the surrounding string literal before recompilation.
	stringSpans := findStringLiteralSpans(expression)
	markers, err := findDSLStringMarkers(expression, data, stringSpans)
	if err != nil {
		return "", err
	}

	if len(markers) == 0 {
		return "", fmt.Errorf("unresolved DSL placeholders must be inside string literals")
	}

	sort.Slice(markers, func(i, j int) bool {
		return markers[i].start > markers[j].start
	})

	resolved := expression
	for _, marker := range markers {
		result, err := render.Render(render.Input{
			Text:   "{{" + marker.expr + "}}",
			Values: data,
		})
		if err != nil {
			return "", err
		}

		replacement := expressions.EscapeStringValue(result.Text, marker.quote)
		resolved = resolved[:marker.start] + replacement + resolved[marker.end:]
	}

	return resolved, nil
}

func findDSLStringMarkers(expression string, data map[string]interface{}, stringSpans []stringLiteralSpan) ([]dslStringMarker, error) {
	var markers []dslStringMarker
	var occupiedSpans []textSpan

	seenComplex := make(map[string]struct{})

	for _, expr := range expressions.FindExpressions(expression, "{{", "}}", data) {
		if _, ok := seenComplex[expr]; ok {
			continue
		}
		seenComplex[expr] = struct{}{}

		marker := "{{" + expr + "}}"
		for start := 0; ; {
			index := strings.Index(expression[start:], marker)
			if index < 0 {
				break
			}

			index += start
			end := index + len(marker)

			stringSpan, ok := stringLiteralForSpan(stringSpans, index, end)
			if !ok {
				return nil, fmt.Errorf("unresolved DSL placeholder %q is not inside a string literal", expr)
			}

			got := dslStringMarker{start: index, end: end, expr: expr, quote: stringSpan.quote}
			markers = append(markers, got)
			occupiedSpans = append(occupiedSpans, textSpan{start: index, end: end})
			start = end
		}
	}

	for _, match := range dslStringMarkerRegex.FindAllStringSubmatchIndex(expression, -1) {
		if len(match) < 4 || markerWithinSpans(match[0], match[1], occupiedSpans) {
			continue
		}

		stringSpan, ok := stringLiteralForSpan(stringSpans, match[0], match[1])
		if !ok {
			return nil, fmt.Errorf("unresolved DSL placeholder %q is not inside a string literal", expression[match[2]:match[3]])
		}

		markers = append(markers, dslStringMarker{
			start: match[0],
			end:   match[1],
			expr:  expression[match[2]:match[3]],
			quote: stringSpan.quote,
		})
	}

	return markers, nil
}

func markerWithinSpans(start, end int, spans []textSpan) bool {
	for _, span := range spans {
		if start >= span.start && end <= span.end {
			return true
		}
	}

	return false
}

func findStringLiteralSpans(expression string) []stringLiteralSpan {
	var spans []stringLiteralSpan
	var quote byte
	start := 0
	escaped := false

	for i := 0; i < len(expression); i++ {
		char := expression[i]
		if escaped {
			escaped = false
			continue
		}

		if char == '\\' {
			escaped = true
			continue
		}

		if quote != 0 {
			if char == quote {
				spans = append(spans, stringLiteralSpan{start: start, end: i, quote: quote})
				quote = 0
			}
			continue
		}

		if char == '\'' || char == '"' {
			quote = char
			start = i + 1
		}
	}

	if quote != 0 {
		spans = append(spans, stringLiteralSpan{start: start, end: len(expression), quote: quote})
	}

	return spans
}

func stringLiteralForSpan(spans []stringLiteralSpan, start, end int) (stringLiteralSpan, bool) {
	for _, span := range spans {
		if start >= span.start && end <= span.end {
			return span, true
		}
	}

	return stringLiteralSpan{}, false
}
