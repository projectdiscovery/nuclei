package output

import (
	jsoniter "github.com/json-iterator/go"
)

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	if !w.jsonReqResp { // don't show request-response in json if not asked
		output.Request = ""
		output.Response = ""
	}
	return jsoniter.Marshal(output)
}
