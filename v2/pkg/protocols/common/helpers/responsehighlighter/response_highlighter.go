package responsehighlighter

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

var colorizer = aurora.NewAurora(true)

func Highlight(operatorResult *operators.Result, response string, noColor, hexdump bool) string {
	result := response
	if operatorResult != nil && !noColor {
		for _, matches := range operatorResult.Matches {
			if len(matches) > 0 {
				for _, currentMatch := range matches {
					if hexdump {
						currentMatchEncoded := chunkSplit(hex.EncodeToString([]byte(currentMatch)), 2, " ")
						result = strings.ReplaceAll(result, currentMatchEncoded, colorizer.Green(currentMatchEncoded).String())
					}
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

// chunkSplit splits a string into smaller chunks
func chunkSplit(body string, chunklen uint, end string) string {
	if end == "" {
		end = "\r\n"
	}
	runes, erunes := []rune(body), []rune(end)
	l := uint(len(runes))
	if l <= 1 || l < chunklen {
		return body + end
	}
	ns := make([]rune, 0, len(runes)+len(erunes))
	var i uint
	for i = 0; i < l; i += chunklen {
		if i+chunklen > l {
			ns = append(ns, runes[i:]...)
		} else {
			ns = append(ns, runes[i:i+chunklen]...)
		}
		ns = append(ns, erunes...)
	}
	return string(ns)
}
