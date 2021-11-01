package responsehighlighter

import (
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

var colorFunction = aurora.Green

func Highlight(operatorResult *operators.Result, response string, noColor, hexDump bool) string {
	result := response
	if operatorResult != nil && !noColor {
		for _, matches := range operatorResult.Matches {
			if len(matches) > 0 {
				for _, currentMatch := range matches {
					if hexDump {
						highlightedHexDump, err := toHighLightedHexDump(result, currentMatch)
						if err == nil {
							result = highlightedHexDump.String()
						}
					} else {
						result = strings.ReplaceAll(result, currentMatch, addColor(currentMatch))
					}
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

func addColor(value string) string {
	return colorFunction(value).String()
}
