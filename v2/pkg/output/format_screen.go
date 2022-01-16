package output

import (
	"bytes"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// formatScreen formats the output for showing on screen.
func (w *StandardWriter) formatScreen(output *ResultEvent) []byte {
	builder := &bytes.Buffer{}

	if !w.noMetadata {
		if !w.noTimestamp {
			builder.WriteRune('[')
			builder.WriteString(w.aurora.Cyan(output.Timestamp.Format("2006-01-02 15:04:05")).String())
			builder.WriteString("] ")
		}
		builder.WriteRune('[')
		builder.WriteString(w.aurora.BrightGreen(output.TemplateID).String())

		if output.MatcherName != "" {
			builder.WriteString(":")
			builder.WriteString(w.aurora.BrightGreen(output.MatcherName).Bold().String())
		} else if output.ExtractorName != "" {
			builder.WriteString(":")
			builder.WriteString(w.aurora.BrightGreen(output.ExtractorName).Bold().String())
		}

		if w.matcherStatus {
			builder.WriteString("] [")
			if !output.MatcherStatus {
				builder.WriteString(w.aurora.Red("failed").String())
			} else {
				builder.WriteString(w.aurora.Green("matched").String())
			}
		}

		builder.WriteString("] [")
		builder.WriteString(w.aurora.BrightBlue(output.Type).String())
		builder.WriteString("] ")

		builder.WriteString("[")
		builder.WriteString(w.severityColors(output.Info.SeverityHolder.Severity))
		builder.WriteString("] ")
	}
	if output.Matched != "" {
		builder.WriteString(output.Matched)
	} else {
		builder.WriteString(output.Host)
	}

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

	if output.LineCount != "" {
		builder.WriteString(" [Lines: ")
		builder.WriteString(output.LineCount)
		builder.WriteString("]")
	}

	// Write meta if any
	if len(output.Metadata) > 0 {
		builder.WriteString(" [")

		first := true
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
	return builder.Bytes()
}
