package templates

import (
	"fmt"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

var (
	Colorizer         aurora.Aurora
	SeverityColorizer func(severity.Severity) string
)

// TemplateLogMessage returns a beautified log string for a template
func TemplateLogMessage(id, name string, authors []string, templateSeverity severity.Severity) string {
	if Colorizer == nil || SeverityColorizer == nil {
		return ""
	}
	// Display the message for the template
	return fmt.Sprintf("[%s] %s (%s) [%s]",
		Colorizer.BrightBlue(id).String(),
		Colorizer.Bold(name).String(),
		Colorizer.BrightYellow(appendAtSignToAuthors(authors)).String(),
		SeverityColorizer(templateSeverity))
}

// appendAtSignToAuthors appends @ before each author and returns the final string
func appendAtSignToAuthors(authors []string) string {
	if len(authors) == 0 {
		return "@none"
	}

	values := make([]string, 0, len(authors))
	for _, k := range authors {
		if !strings.HasPrefix(k, "@") {
			values = append(values, fmt.Sprintf("@%s", k))
		} else {
			values = append(values, k)
		}
	}
	return strings.Join(values, ",")
}
