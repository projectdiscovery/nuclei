package replacer

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Replace replaces placeholders in template with values on the fly.
func Replace(template string, values map[string]interface{}) string {
	var replacerItems []string

	builder := &strings.Builder{}
	for key, val := range values {
		builder.WriteString(marker.ParenthesisOpen)
		builder.WriteString(key)
		builder.WriteString(marker.ParenthesisClose)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, types.ToString(val))

		builder.WriteString(marker.General)
		builder.WriteString(key)
		builder.WriteString(marker.General)
		replacerItems = append(replacerItems, builder.String())
		builder.Reset()
		replacerItems = append(replacerItems, types.ToString(val))
	}
	replacer := strings.NewReplacer(replacerItems...)
	final := replacer.Replace(template)
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
