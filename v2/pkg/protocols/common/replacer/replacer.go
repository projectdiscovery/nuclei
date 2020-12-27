package replacer

import (
	"fmt"
	"strings"
)

// Payload marker constants
const (
	MarkerGeneral          = "§"
	MarkerParenthesisOpen  = "{{"
	MarkerParenthesisClose = "}}"
)

// New creates a new replacer structure for values replacement on the fly.
func New(values map[string]interface{}) *strings.Replacer {
	replacerItems := make([]string, 0, len(values)*4)

	for key, val := range values {
		valueStr := fmt.Sprintf("%s", val)

		replacerItems = append(replacerItems,
			fmt.Sprintf("%s%s%s", MarkerParenthesisOpen, key, MarkerParenthesisClose),
			valueStr,
		)
		replacerItems = append(replacerItems,
			fmt.Sprintf("%s%s%s", MarkerGeneral, key, MarkerGeneral),
			valueStr,
		)
	}
	return strings.NewReplacer(replacerItems...)
}
