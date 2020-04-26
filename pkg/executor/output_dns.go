package executor

import (
	"strings"
)

// buildOutput builds an output text for writing results
func (e *DNSExecutor) buildOutputDNS(domain string, extractorResults []string) string {
	builder := &strings.Builder{}
	builder.WriteRune('[')
	builder.WriteString(e.template.ID)
	builder.WriteString("] [dns] ")

	builder.WriteString(domain)

	// If any extractors, write the results
	if len(extractorResults) > 0 {
		builder.WriteString(" [")
		for i, result := range extractorResults {
			builder.WriteString(result)
			if i != len(extractorResults)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteString("]")
	}
	builder.WriteRune('\n')

	return builder.String()
}
