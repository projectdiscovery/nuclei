package executor

import (
	"strings"

	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"github.com/projectdiscovery/retryablehttp-go"
)

// buildOutputHTTP builds an output text for writing results
func (e *HTTPExecutor) buildOutputHTTP(req *retryablehttp.Request, extractorResults []string, matcher *matchers.Matcher) string {
	builder := &strings.Builder{}

	builder.WriteRune('[')
	builder.WriteString(e.template.ID)
	if len(matcher.Name) > 0 {
		builder.WriteString(":")
		builder.WriteString(matcher.Name)
	}
	builder.WriteString("] [http] ")

	// Escape the URL by replacing all % with %%
	URL := req.URL.String()
	escapedURL := strings.Replace(URL, "%", "%%", -1)
	builder.WriteString(escapedURL)

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
