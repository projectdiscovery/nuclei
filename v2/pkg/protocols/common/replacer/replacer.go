package replacer

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Payload marker constants
const (
	MarkerGeneral          = "§"
	MarkerParenthesisOpen  = "{{"
	MarkerParenthesisClose = "}}"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	var replacerItems []string

	builder := &strings.Builder{}
	for key, val := range values {
		builder.WriteString(MarkerParenthesisOpen)
		builder.WriteString(key)
		builder.WriteString(MarkerParenthesisClose)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, types.ToString(val))

		builder.WriteString(MarkerGeneral)
		builder.WriteString(key)
		builder.WriteString(MarkerGeneral)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, types.ToString(val))
	}
	replacer := strings.NewReplacer(replacerItems...)
	final := replacer.Replace(template)
	return final
}
