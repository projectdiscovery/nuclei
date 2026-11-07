package output

import (
	"fmt"

	json "github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	if !w.jsonReqResp { // don't show request-response in json if not asked
		output.Request = ""
		output.Response = ""
	}
	if len(output.Info.Metadata) > 0 {
		output.Info.Metadata = sanitizeMetadataForJSON(output.Info.Metadata)
	}
	if len(output.Metadata) > 0 {
		output.Metadata = sanitizeMetadataForJSON(output.Metadata)
	}
	return json.Marshal(output)
}

// sanitizeMetadataForJSON normalizes any map[interface{}]interface{} or nested
// collections in metadata to map[string]interface{}, ensuring JSON encoders
// (such as sonic or standard encoding/json) can serialize them without error (#7971).
func sanitizeMetadataForJSON(m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return m
	}
	sanitized := sanitizeJSONValue(m)
	if res, ok := sanitized.(map[string]interface{}); ok {
		return res
	}
	return m
}

func sanitizeJSONValue(v interface{}) interface{} {
	switch typed := v.(type) {
	case map[interface{}]interface{}:
		converted := make(map[string]interface{}, len(typed))
		for k, val := range typed {
			converted[fmt.Sprint(k)] = sanitizeJSONValue(val)
		}
		return converted
	case map[string]interface{}:
		converted := make(map[string]interface{}, len(typed))
		for k, val := range typed {
			converted[k] = sanitizeJSONValue(val)
		}
		return converted
	case []interface{}:
		converted := make([]interface{}, len(typed))
		for i, val := range typed {
			converted[i] = sanitizeJSONValue(val)
		}
		return converted
	default:
		return v
	}
}
