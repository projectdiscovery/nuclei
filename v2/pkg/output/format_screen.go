package output

import (
	"bytes"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// formatScreen formats the output for showing on screen.
func (w *StandardWriter) formatScreen(output *ResultEvent) ([]byte, error) {
	builder := &bytes.Buffer{}

	if !w.noMetadata {
		builder.WriteRune('[')
		builder.WriteString(w.aurora.BrightGreen(output.TemplateID).String())

		if output.MatcherName != "" {
			builder.WriteString(":")
			builder.WriteString(w.aurora.BrightGreen(output.MatcherName).Bold().String())
		} else if output.ExtractorName != "" {
			builder.WriteString(":")
			builder.WriteString(w.aurora.BrightGreen(output.ExtractorName).Bold().String())
		}

		builder.WriteString("] [")
		builder.WriteString(w.aurora.BrightBlue(output.Type).String())
		builder.WriteString("] ")

		builder.WriteString("[")
		builder.WriteString(w.severityColors.Data[types.ToString(output.Info["severity"])])
		builder.WriteString("] ")
	}
	builder.WriteString(output.Matched)

	// If any extractors, write the results
	if len(output.ExtractedResults) > 0 {
		builder.WriteString(" [")

		for i, item := range output.ExtractedResults {
			builder.WriteString(w.aurora.BrightCyan(item).String())

			if i != len(output.ExtractedResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}

	// Write meta if any
	if len(output.Metadata) > 0 {
		builder.WriteString(" [")

		var first bool = true
		for name, value := range output.Metadata {
			if !first {
				builder.WriteRune(',')
			}
			first = false

			builder.WriteString(w.aurora.BrightYellow(name).String())
			builder.WriteRune('=')
			builder.WriteString(w.aurora.BrightYellow(types.ToString(value)).String())
		}
		builder.WriteString("]")
	}
	return builder.Bytes(), nil
}
