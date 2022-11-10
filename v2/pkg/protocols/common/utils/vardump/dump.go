package vardump

import (
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// EnableVarDump enables var dump for debugging optionally
var EnableVarDump bool

// DumpVariables writes the truncated dump of variables to a string
// in a formatted key-value manner.
//
// The values are truncated to return 50 characters from start and end.
func DumpVariables(data map[string]interface{}) string {
	var counter int

	buffer := &strings.Builder{}
	buffer.Grow(len(data) * 78) // grow buffer to an approximate size

	builder := &strings.Builder{}
	for k, v := range data {
		valueString := types.ToString(v)

		counter++
		if len(valueString) > 50 {
			builder.Grow(56)
			builder.WriteString(valueString[0:25])
			builder.WriteString(" .... ")
			builder.WriteString(valueString[len(valueString)-25:])
			valueString = builder.String()
			builder.Reset()
		}
		valueString = strings.ReplaceAll(strings.ReplaceAll(valueString, "\r", " "), "\n", " ")

		buffer.WriteString("\t")
		buffer.WriteString(strconv.Itoa(counter))
		buffer.WriteString(". ")
		buffer.WriteString(k)
		buffer.WriteString(" => ")
		buffer.WriteString(valueString)
		buffer.WriteString("\n")
	}
	final := buffer.String()
	return final
}
