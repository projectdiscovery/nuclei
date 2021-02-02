package format

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Summary returns a formatted built one line summary of the event
func Summary(output *output.ResultEvent) string {
	template := GetMatchedTemplate(output)

	builder := &strings.Builder{}
	builder.WriteString("[")
	builder.WriteString(template)
	builder.WriteString("] [")
	builder.WriteString(output.Info["severity"])
	builder.WriteString("] ")
	builder.WriteString(output.Info["name"])
	builder.WriteString(" found on ")
	builder.WriteString(output.Host)
	data := builder.String()
	return data
}

// MarkdownDescription formats a short description of the generated
// event by the nuclei scanner in Markdown format.
func MarkdownDescription(output *output.ResultEvent) string {
	template := GetMatchedTemplate(output)
	builder := &bytes.Buffer{}
	builder.WriteString("**Details**: **")
	builder.WriteString(template)
	builder.WriteString("** ")
	builder.WriteString(" matched at ")
	builder.WriteString(output.Host)
	builder.WriteString("\n\n**Protocol**: ")
	builder.WriteString(strings.ToUpper(output.Type))
	builder.WriteString("\n\n**Full URL**: ")
	builder.WriteString(output.Matched)
	builder.WriteString("\n\n**Timestamp**: ")
	builder.WriteString(output.Timestamp.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	builder.WriteString("\n\n**Template Information**\n\n| Key | Value |\n|---|---|\n")
	for k, v := range output.Info {
		builder.WriteString(fmt.Sprintf("| %s | %s |\n", k, v))
	}
	builder.WriteString("\n**Request**\n\n```\n")
	builder.WriteString(output.Request)
	builder.WriteString("\n```\n\n**Response**\n\n```\n")
	builder.WriteString(output.Response)
	builder.WriteString("\n```\n\n")

	if len(output.ExtractedResults) > 0 || len(output.Metadata) > 0 {
		builder.WriteString("**Extra Information**\n\n")
		if len(output.ExtractedResults) > 0 {
			builder.WriteString("**Extracted results**:\n\n")
			for _, v := range output.ExtractedResults {
				builder.WriteString("- ")
				builder.WriteString(v)
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
		if len(output.Metadata) > 0 {
			builder.WriteString("**Metadata**:\n\n")
			for k, v := range output.Metadata {
				builder.WriteString("- ")
				builder.WriteString(k)
				builder.WriteString(": ")
				builder.WriteString(types.ToString(v))
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
	}
	data := builder.String()
	return data
}

// GetMatchedTemplate returns the matched template from a result event
func GetMatchedTemplate(output *output.ResultEvent) string {
	builder := &strings.Builder{}
	builder.WriteString(output.TemplateID)
	if output.MatcherName != "" {
		builder.WriteString(":")
		builder.WriteString(output.MatcherName)
	}
	if output.ExtractorName != "" {
		builder.WriteString(":")
		builder.WriteString(output.ExtractorName)
	}
	template := builder.String()
	return template
}
