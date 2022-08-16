package vardump

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Variables writes the truncated dump of variables on the stderr
// in a formatted key-value manner using gologger.
//
// The values are truncated to return 50 characters from start and end.
func Variables(data map[string]interface{}) {
	var counter int

	builder := &strings.Builder{}
	for k, v := range data {
		valueString := types.ToString(v)

		counter++
		if len(valueString) > 50 {
			builder.Grow(56) // grow the buffer
			builder.WriteString(valueString[0:25])
			builder.WriteString(" .... ")
			builder.WriteString(valueString[len(valueString)-25:])
			valueString = builder.String()
			builder.Reset()
		}
		valueString = strings.ReplaceAll(valueString, "\n", " ")
		valueString = strings.ReplaceAll(valueString, "\r", " ")
		gologger.Print().Msgf("\t%d. %s => %s", counter, k, valueString)
	}
}
