package templates

import (
	"fmt"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

var (
	Colorizer                       aurora.Aurora
	SeverityColorizer               func(severity.Severity) string
	deprecatedProtocolNameTemplates = map[string]struct{}{} //templates that still use deprecated protocol names
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

// PrintDeprecatedProtocolNameMsgIfApplicable prints a message if deprecated protocol names are used
// Unless mode is silent we print a message for deprecated protocol name
func PrintDeprecatedProtocolNameMsgIfApplicable(isSilent bool, verbose bool) {
	if len(deprecatedProtocolNameTemplates) > 0 && !isSilent {
		gologger.Print().Msgf("[%v] Found %v templates loaded with deprecated protocol syntax, update before v2.9.5 for continued support.\n", aurora.Yellow("WRN").String(), len(deprecatedProtocolNameTemplates))
	}
	if verbose {
		for template := range deprecatedProtocolNameTemplates {
			gologger.Print().Msgf("  - %s\n", template)
		}
	}
	deprecatedProtocolNameTemplates = map[string]struct{}{}
}
