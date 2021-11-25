package responsehighlighter

import (
	"sort"
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

var colorFunction = aurora.Green

func Highlight(operatorResult *operators.Result, response string, noColor, hexDump bool) string {
	result := response
	if operatorResult != nil && !noColor {
		for _, currentMatch := range getSortedMatches(operatorResult) {
			if hexDump {
				highlightedHexDump, err := toHighLightedHexDump(result, currentMatch)
				if err == nil {
					result = highlightedHexDump.String()
				}
			} else {
				result = highlightASCII(currentMatch, result)
			}
		}
	}

	return result
}

func highlightASCII(currentMatch string, result string) string {
	var coloredMatchBuilder strings.Builder
	for _, char := range currentMatch {
		coloredMatchBuilder.WriteString(addColor(string(char)))
	}

	return strings.ReplaceAll(result, currentMatch, coloredMatchBuilder.String())
}

func getSortedMatches(operatorResult *operators.Result) []string {
	sortedMatches := make([]string, 0, len(operatorResult.Matches))
	for _, matches := range operatorResult.Matches {
		sortedMatches = append(sortedMatches, matches...)
	}

	sort.Slice(sortedMatches, func(i, j int) bool {
		return len(sortedMatches[i]) > len(sortedMatches[j])
	})
	return sortedMatches
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
