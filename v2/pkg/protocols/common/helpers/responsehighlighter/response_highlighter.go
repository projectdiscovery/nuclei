package responsehighlighter

import (
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

var colorizer = aurora.NewAurora(true)

func Highlight(operatorResult *operators.Result, response string, noColor bool) string {
	result := response
	if operatorResult != nil && !noColor {
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

func CreateStatusCodeSnippet(response string, statusCode int) string {
	if strings.HasPrefix(response, "HTTP/") {
		strStatusCode := strconv.Itoa(statusCode)
		return response[:strings.Index(response, strStatusCode)+len(strStatusCode)]
	}
	return ""
}
