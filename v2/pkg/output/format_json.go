package output

import (
	jsoniter "github.com/json-iterator/go"
)

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	return jsoniter.Marshal(output)
}
