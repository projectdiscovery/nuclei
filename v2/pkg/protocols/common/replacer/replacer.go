package replacer

import (
	"fmt"
	"strings"
)

const (
	markerGeneral          = "§"
	markerParenthesisOpen  = "{{"
	markerParenthesisClose = "}}"
)

// New creates a new replacer structure for values replacement on the fly.
func New(values map[string]interface{}) *strings.Replacer {
	replacerItems := make([]string, 0, len(values)*4)

	for key, val := range values {
		valueStr := fmt.Sprintf("%s", val)

		replacerItems = append(replacerItems,
			fmt.Sprintf("%s%s%s", markerParenthesisOpen, key, markerParenthesisClose),
			valueStr,
		)
		replacerItems = append(replacerItems,
			fmt.Sprintf("%s%s%s", markerGeneral, key, markerGeneral),
			valueStr,
		)
	}
	return strings.NewReplacer(replacerItems...)
}
