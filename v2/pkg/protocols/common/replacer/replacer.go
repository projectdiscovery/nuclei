package replacer

import (
	"strings"

	"github.com/projectdiscovery/fasttemplate"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	valuesMap := make(map[string]interface{}, len(values))
	for k, v := range values {
		valuesMap[k] = types.ToString(v)
	}
	replaced := fasttemplate.ExecuteStringStd(template, marker.ParenthesisOpen, marker.ParenthesisClose, valuesMap)
	final := fasttemplate.ExecuteStringStd(replaced, marker.General, marker.General, valuesMap)
	return final
}

// Replace replaces one placeholder in template with one value on the fly.
func ReplaceOne(template string, key string, value interface{}) string {
	data := replaceOneWithMarkers(template, key, value, marker.ParenthesisOpen, marker.ParenthesisClose)
	return replaceOneWithMarkers(data, key, value, marker.General, marker.General)
}

// replaceOneWithMarkers is a helper function that perform one time replacement
func replaceOneWithMarkers(template, key string, value interface{}, openMarker, closeMarker string) string {
	return strings.Replace(template, openMarker+key+closeMarker, types.ToString(value), 1)
}
