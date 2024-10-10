package output

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// formatScreen formats the output for showing on screen.
func (w *StandardWriter) formatScreen(output *ResultEvent) []byte {
	builder := &bytes.Buffer{}

	if !w.noMetadata {
		if w.timestamp {
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

		if output.GlobalMatchers {
			builder.WriteString("] [")
			builder.WriteString(w.aurora.BrightMagenta("global").String())
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
			// trim trailing space
			// quote non-ascii and non printable characters and then
			// unquote quotes (`"`) for readability
			item = strings.TrimSpace(item)
			item = strconv.QuoteToASCII(item)
			item = strings.ReplaceAll(item, `\"`, `"`)

			builder.WriteString(w.aurora.BrightCyan(item).String())

			if i != len(output.ExtractedResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}

	if len(output.Lines) > 0 {
		builder.WriteString(" [LN: ")

		for i, line := range output.Lines {
			builder.WriteString(strconv.Itoa(line))

			if i != len(output.Lines)-1 {
				builder.WriteString(",")
			}
		}
		builder.WriteString("]")
	}

	// Write meta if any
	if len(output.Metadata) > 0 {
		builder.WriteString(" [")

		first := true
		// sort to get predictable output
		for _, name := range mapsutil.GetSortedKeys(output.Metadata) {
			value := output.Metadata[name]
			if !first {
				builder.WriteRune(',')
			}
			first = false

			builder.WriteString(w.aurora.BrightYellow(name).String())
			builder.WriteRune('=')
			builder.WriteString(w.aurora.BrightYellow(strconv.QuoteToASCII(types.ToString(value))).String())
		}
		builder.WriteString("]")
	}

	// If it is a fuzzing output, enrich with additional
	// metadata for the match.
	if output.IsFuzzingResult {
		if output.FuzzingParameter != "" {
			builder.WriteString(" [")
			builder.WriteString(output.FuzzingPosition)
			builder.WriteRune(':')
			builder.WriteString(w.aurora.BrightMagenta(output.FuzzingParameter).String())
			builder.WriteString("]")
		}

		builder.WriteString(" [")
		builder.WriteString(output.FuzzingMethod)
		builder.WriteString("]")
	}
	return builder.Bytes()
}
