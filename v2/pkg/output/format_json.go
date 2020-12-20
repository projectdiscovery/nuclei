package output

import jsoniter "github.com/json-iterator/go"

var jsoniterCfg jsoniter.API

func init() {
	jsoniterCfg = jsoniter.Config{SortMapKeys: true}.Froze()
}

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output Event) ([]byte, error) {
	return jsoniterCfg.Marshal(output)
}
