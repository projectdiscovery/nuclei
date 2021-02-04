package replacer

import (
	"github.com/valyala/fasttemplate"
)

// Payload marker constants
const (
	MarkerGeneral          = "§"
	MarkerParenthesisOpen  = "{{"
	MarkerParenthesisClose = "}}"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	new := fasttemplate.ExecuteStringStd(template, MarkerGeneral, MarkerGeneral, values)
	final := fasttemplate.ExecuteStringStd(new, MarkerParenthesisOpen, MarkerParenthesisClose, values)
	return final
}
