package replacer

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
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

// ReplaceNth replaces nth placeholder with value and other with key,
// returning parsed template and the total number of placeholders encountered.
func ReplaceNth(template, key, value string, n int) (string, int) {
	regex := utils.PlaceholderRegex(key)

	totalCount := 0
	i := 0
	for m := 1; i < len(template); m++ {
		loc := regex.FindStringIndex(template[i:])
		if len(loc) < 2 {
			break
		}
		totalCount++
		i += loc[0]
		if m == n {
			template = template[:i] + value + template[i+(loc[1]-loc[0]):]
			i += len(value)
		} else {
			template = template[:i] + key + template[i+(loc[1]-loc[0]):]
			i += len(key)
		}
	}
	return template, totalCount
}
