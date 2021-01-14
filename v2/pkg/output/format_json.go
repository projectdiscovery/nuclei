package output

import (
	"time"

	jsoniter "github.com/json-iterator/go"
)

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	output.Timestamp = time.Now()
	return jsoniter.Marshal(output)
}
