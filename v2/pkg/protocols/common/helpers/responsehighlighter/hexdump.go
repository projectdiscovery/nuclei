package responsehighlighter

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/projectdiscovery/gologger"
)

// [0-9a-fA-F]{8} {2} 	- hexdump indexes (8 character hex value followed by two spaces)
// [0-9a-fA-F]{2} + 	- 2 character long hex values followed by one or two space (potentially wrapped with an ASCII color code, see below)
// \x1b\[(\d;?)+m 		- ASCII color code pattern
// \x1b\[0m   	  		- ASCII color code reset
// \|(.*)\|\n			- ASCII representation of the input delimited by pipe characters
var hexDumpParsePattern = regexp.MustCompile(`([0-9a-fA-F]{8} {2})((?:(?:\x1b\[(?:\d;?)+m)?[0-9a-fA-F]{2}(?:\x1b\[0m)? +)+)\|(.*)\|\n`)
var hexValuePattern = regexp.MustCompile(`([a-fA-F0-9]{2})`)

type HighlightableHexDump struct {
	index []string
	hex   []string
	ascii []string
}

func NewHighlightableHexDump(rowSize int) HighlightableHexDump {
	return HighlightableHexDump{index: make([]string, 0, rowSize), hex: make([]string, 0, rowSize), ascii: make([]string, 0, rowSize)}
}

func (hexDump HighlightableHexDump) len() int {
	return len(hexDump.index)
}

func (hexDump HighlightableHexDump) String() string {
	var result string
	for i := 0; i < hexDump.len(); i++ {
		result += hexDump.index[i] + hexDump.hex[i] + "|" + hexDump.ascii[i] + "|\n"
	}
	return result
}

func toHighLightedHexDump(hexDump, snippetToHighlight string) (HighlightableHexDump, error) {
	hexDumpRowValues := hexDumpParsePattern.FindAllStringSubmatch(hexDump, -1)
	if hexDumpRowValues == nil || len(hexDumpRowValues) != strings.Count(hexDump, "\n") {
		message := "could not parse hexdump"
		gologger.Warning().Msgf(message)
		return HighlightableHexDump{}, errors.New(message)
	}

	result := NewHighlightableHexDump(len(hexDumpRowValues))
	for _, currentHexDumpRowValues := range hexDumpRowValues {
		result.index = append(result.index, currentHexDumpRowValues[1])
		result.hex = append(result.hex, currentHexDumpRowValues[2])
		result.ascii = append(result.ascii, currentHexDumpRowValues[3])
	}
	return result.highlight(snippetToHighlight), nil
}

func (hexDump HighlightableHexDump) highlight(snippetToColor string) HighlightableHexDump {
	return highlightAsciiSection(highlightHexSection(hexDump, snippetToColor), snippetToColor)
}

func highlightHexSection(hexDump HighlightableHexDump, snippetToColor string) HighlightableHexDump {
	var snippetHexCharactersMatchPattern string
	for _, char := range snippetToColor {
		snippetHexCharactersMatchPattern += fmt.Sprintf(`(%02x[ \n]+)`, char)
	}

	hexDump.hex = highlight(hexDump.hex, snippetHexCharactersMatchPattern, func(v string) string {
		return hexValuePattern.ReplaceAllString(v, addColor("$1"))
	})

	return hexDump
}

func highlightAsciiSection(hexDump HighlightableHexDump, snippetToColor string) HighlightableHexDump {
	var snippetCharactersMatchPattern string
	for _, v := range snippetToColor {
		var value string
		if IsASCIIPrintable(v) {
			value = regexp.QuoteMeta(string(v))
		} else {
			value = "."
		}
		snippetCharactersMatchPattern += fmt.Sprintf(`(%s\n*)`, value)
	}

	hexDump.ascii = highlight(hexDump.ascii, snippetCharactersMatchPattern, func(v string) string {
		if len(v) > 1 {
			return addColor(string(v[0])) + v[1:] // do not color new line characters
		}
		return addColor(v)
	})

	return hexDump
}

func highlight(values []string, snippetCharactersMatchPattern string, replaceToFunc func(v string) string) []string {
	rows := strings.Join(values, "\n")
	compiledPattern := regexp.MustCompile(snippetCharactersMatchPattern)
	for _, submatch := range compiledPattern.FindAllStringSubmatch(rows, -1) {
		var replaceTo string
		var replaceFrom string
		for _, matchedValueWithSuffix := range submatch[1:] {
			replaceFrom += matchedValueWithSuffix
			replaceTo += replaceToFunc(matchedValueWithSuffix)
		}
		rows = strings.ReplaceAll(rows, replaceFrom, replaceTo)
	}
	return strings.Split(rows, "\n")
}

func HasBinaryContent(input string) bool {
	return !IsASCII(input)
}

// IsASCII tests whether a string consists only of ASCII characters or not
func IsASCII(input string) bool {
	for i := 0; i < len(input); i++ {
		if input[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func IsASCIIPrintable(input rune) bool {
	return input > 32 && input < unicode.MaxASCII
}
