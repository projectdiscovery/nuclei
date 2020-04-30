package requests

import (
	"fmt"
	"strings"
)

func newReplacer(values map[string]interface{}) *strings.Replacer {
	var replacerItems []string
	for k, v := range values {
		replacerItems = append(replacerItems, fmt.Sprintf("{{%s}}", k))
		replacerItems = append(replacerItems, fmt.Sprintf("%s", v))
	}

	return strings.NewReplacer(replacerItems...)
}
