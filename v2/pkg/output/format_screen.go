package output

import (
	"bytes"
	"errors"

	"github.com/spf13/cast"
)

// formatScreen formats the output for showing on screen.
func (w *StandardWriter) formatScreen(output Event) ([]byte, error) {
	builder := &bytes.Buffer{}

	if !w.noMetadata {
		id, ok := output["id"]
		if !ok {
			return nil, errors.New("no template id found")
		}
		builder.WriteRune('[')
		builder.WriteString(w.aurora.BrightGreen(id.(string)).String())

		matcherName, ok := output["matcher_name"]
		if ok && matcherName != "" {
			builder.WriteString(":")
			builder.WriteString(w.aurora.BrightGreen(matcherName).Bold().String())
		}

		outputType, ok := output["type"]
		if !ok {
			return nil, errors.New("no output type found")
		}
		builder.WriteString("] [")
		builder.WriteString(w.aurora.BrightBlue(outputType.(string)).String())
		builder.WriteString("] ")

		severity, ok := output["severity"]
		if !ok {
			return nil, errors.New("no output severity found")
		}
		builder.WriteString("[")
		builder.WriteString(w.severityMap[severity.(string)])
		builder.WriteString("] ")
	}
	matched, ok := output["matched"]
	if !ok {
		return nil, errors.New("no matched url found")
	}
	builder.WriteString(matched.(string))

	// If any extractors, write the results
	extractedResults, ok := output["extracted_results"]
	if ok {
		builder.WriteString(" [")

		extractorResults := cast.ToStringSlice(extractedResults)
		for i, item := range extractorResults {
			builder.WriteString(w.aurora.BrightCyan(item).String())

			if i != len(extractorResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}

	// Write meta if any
	metaResults, ok := output["meta"]
	if ok {
		builder.WriteString(" [")

		metaResults := cast.ToStringMap(metaResults)

		var first = true
		for name, value := range metaResults {
			if first {
				builder.WriteRune(',')
			}
			first = false

			builder.WriteString(w.aurora.BrightYellow(name).String())
			builder.WriteRune('=')
			builder.WriteString(w.aurora.BrightYellow(cast.ToString(value)).String())
		}
		builder.WriteString("]")
	}
	return builder.Bytes(), nil
}
