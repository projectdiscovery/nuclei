package responsehighlighter

import (
	"fmt"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

func Highlight(operatorResult *operators.Result, response string, noColor bool) string {
	result := response
	if operatorResult != nil && !noColor {
		colorizer := aurora.NewAurora(true)
		for _, matches := range operatorResult.Matches {
			if len(matches) > 0 {
				for _, currentMatch := range matches {
					result = strings.ReplaceAll(result, currentMatch, colorizer.Green(currentMatch).String())
				}
			}
		}
	}

	return result
}

func CreateHTTPStatusMatcherSnippets(statusCode int) []string {
	httpVersions := []string{"0.9", "1.0", "1.1", "2", "2.0", "3", "3.0"}
	var matcherValues = make([]string, 0, len(httpVersions))

	for _, httpVersion := range httpVersions {
		matcherValues = append(matcherValues, fmt.Sprintf("HTTP/%s %d", httpVersion, statusCode))
	}

	return matcherValues
}
