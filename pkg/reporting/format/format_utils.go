package format

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	unitutils "github.com/projectdiscovery/utils/unit"
)

// Summary returns a formatted built one line summary of the event
func Summary(event *output.ResultEvent) string {
	return fmt.Sprintf("%s (%s) found on %s", types.ToString(event.Info.Name), GetMatchedTemplateName(event), event.Host)
}

// GetMatchedTemplateName returns the matched template name from a result event
// together with the found matcher and extractor name, if present
func GetMatchedTemplateName(event *output.ResultEvent) string {
	matchedTemplateName := event.TemplateID
	if event.MatcherName != "" {
		matchedTemplateName += ":" + event.MatcherName
	}

	if event.ExtractorName != "" {
		matchedTemplateName += ":" + event.ExtractorName
	}

	return matchedTemplateName
}

type reportMetadataEditorHook func(event *output.ResultEvent, formatter ResultFormatter) string

var (
	// ReportGenerationMetadataHooks are the hooks for adding metadata to the report
	ReportGenerationMetadataHooks []reportMetadataEditorHook
)

func CreateReportDescription(event *output.ResultEvent, formatter ResultFormatter, omitRaw bool) string {
	template := GetMatchedTemplateName(event)
	builder := &bytes.Buffer{}
	builder.WriteString(fmt.Sprintf("%s: %s matched at %s\n\n", formatter.MakeBold("Details"), formatter.MakeBold(template), event.Host))

	attributes := utils.NewEmptyInsertionOrderedStringMap(3)
	attributes.Set("Protocol", strings.ToUpper(event.Type))
	attributes.Set("Full URL", event.Matched)
	attributes.Set("Timestamp", event.Timestamp.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	attributes.ForEach(func(key string, data interface{}) {
		builder.WriteString(fmt.Sprintf("%s: %s\n\n", formatter.MakeBold(key), types.ToString(data)))
	})

	if len(ReportGenerationMetadataHooks) > 0 {
		for _, hook := range ReportGenerationMetadataHooks {
			builder.WriteString(hook(event, formatter))
		}
	}

	builder.WriteString(formatter.MakeBold("Template Information"))
	builder.WriteString("\n\n")
	builder.WriteString(CreateTemplateInfoTable(&event.Info, formatter))

	if !omitRaw {
		if event.Request != "" {
			builder.WriteString(formatter.CreateCodeBlock("Request", types.ToHexOrString(event.Request), "http"))
		}
		if event.Response != "" {
			var responseString string
			// If the response is larger than 5 kb, truncate it before writing.
			maxKbSize := 5 * unitutils.Kilo
			if len(event.Response) > maxKbSize {
				responseString = event.Response[:maxKbSize]
				responseString += ".... Truncated ...."
			} else {
				responseString = event.Response
			}
			builder.WriteString(formatter.CreateCodeBlock("Response", responseString, "http"))
		}
	}

	if len(event.ExtractedResults) > 0 || len(event.Metadata) > 0 || event.AnalyzerDetails != "" {
		builder.WriteString("\n")
		builder.WriteString(formatter.MakeBold("Extra Information"))
		builder.WriteString("\n\n")

		if len(event.ExtractedResults) > 0 {
			builder.WriteString(formatter.MakeBold("Extracted results:"))
			builder.WriteString("\n\n")

			for _, v := range event.ExtractedResults {
				builder.WriteString("- ")
				builder.WriteString(v)
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
		if event.AnalyzerDetails != "" {
			builder.WriteString(formatter.MakeBold("Analyzer Details:"))
			builder.WriteString("\n\n")

			builder.WriteString(event.AnalyzerDetails)
			builder.WriteString("\n")
		}
		if len(event.Metadata) > 0 {
			builder.WriteString(formatter.MakeBold("Metadata:"))
			builder.WriteString("\n\n")
			for k, v := range event.Metadata {
				builder.WriteString("- ")
				builder.WriteString(k)
				builder.WriteString(": ")
				builder.WriteString(types.ToString(v))
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
	}
	if event.Interaction != nil {
		builder.WriteString(fmt.Sprintf("%s\n%s", formatter.MakeBold("Interaction Data"), formatter.CreateHorizontalLine()))
		builder.WriteString(event.Interaction.Protocol)
		if event.Interaction.QType != "" {
			builder.WriteString(fmt.Sprintf(" (%s)", event.Interaction.QType))
		}
		builder.WriteString(fmt.Sprintf(" Interaction from %s at %s", event.Interaction.RemoteAddress, event.Interaction.UniqueID))

		if event.Interaction.RawRequest != "" {
			builder.WriteString(formatter.CreateCodeBlock("Interaction Request", event.Interaction.RawRequest, ""))
		}
		if event.Interaction.RawResponse != "" {
			builder.WriteString(formatter.CreateCodeBlock("Interaction Response", event.Interaction.RawResponse, ""))
		}
	}

	reference := event.Info.Reference
	if reference != nil && !reference.IsEmpty() {
		builder.WriteString("\nReferences: \n")

		referenceSlice := reference.ToSlice()
		for i, item := range referenceSlice {
			builder.WriteString("- ")
			builder.WriteString(item)
			if len(referenceSlice)-1 != i {
				builder.WriteString("\n")
			}
		}
	}
	builder.WriteString("\n")

	if event.CURLCommand != "" {
		builder.WriteString(
			formatter.CreateCodeBlock("CURL command", types.ToHexOrString(event.CURLCommand), "sh"),
		)
	}

	builder.WriteString("\n" + formatter.CreateHorizontalLine() + "\n")
	builder.WriteString(fmt.Sprintf("Generated by %s", formatter.CreateLink("Nuclei "+config.Version, "https://github.com/projectdiscovery/nuclei")))
	data := builder.String()
	return data
}

func CreateTemplateInfoTable(templateInfo *model.Info, formatter ResultFormatter) string {
	rows := [][]string{
		{"Name", templateInfo.Name},
		{"Authors", templateInfo.Authors.String()},
		{"Tags", templateInfo.Tags.String()},
		{"Severity", templateInfo.SeverityHolder.Severity.String()},
	}

	if !utils.IsBlank(templateInfo.Description) {
		rows = append(rows, []string{"Description", lineBreakToHTML(templateInfo.Description)})
	}

	if !utils.IsBlank(templateInfo.Remediation) {
		rows = append(rows, []string{"Remediation", lineBreakToHTML(templateInfo.Remediation)})
	}

	classification := templateInfo.Classification
	if classification != nil {
		if classification.CVSSMetrics != "" {
			rows = append(rows, []string{"CVSS-Metrics", generateCVSSMetricsFromClassification(classification)})
		}

		rows = append(rows, generateCVECWEIDLinksFromClassification(classification)...)
		rows = append(rows, []string{"CVSS-Score", strconv.FormatFloat(classification.CVSSScore, 'f', 2, 64)})
	}

	for key, value := range templateInfo.Metadata {
		switch value := value.(type) {
		case string:
			if !utils.IsBlank(value) {
				rows = append(rows, []string{key, value})
			}
		}
	}

	table, _ := formatter.CreateTable([]string{"Key", "Value"}, rows)

	return table
}

func generateCVSSMetricsFromClassification(classification *model.Classification) string {
	var cvssLinkPrefix string
	if strings.Contains(classification.CVSSMetrics, "CVSS:3.0") {
		cvssLinkPrefix = "https://www.first.org/cvss/calculator/3.0#"
	} else if strings.Contains(classification.CVSSMetrics, "CVSS:3.1") {
		cvssLinkPrefix = "https://www.first.org/cvss/calculator/3.1#"
	}

	if cvssLinkPrefix == "" {
		return classification.CVSSMetrics
	} else {
		return util.CreateLink(classification.CVSSMetrics, cvssLinkPrefix+classification.CVSSMetrics)
	}
}

func generateCVECWEIDLinksFromClassification(classification *model.Classification) [][]string {
	cwes := classification.CWEID.ToSlice()

	cweIDs := make([]string, 0, len(cwes))
	for _, value := range cwes {
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			continue
		}
		cweIDs = append(cweIDs, util.CreateLink(strings.ToUpper(value), fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", parts[1])))
	}

	var rows [][]string

	if len(cweIDs) > 0 {
		rows = append(rows, []string{"CWE-ID", strings.Join(cweIDs, ",")})
	}

	cves := classification.CVEID.ToSlice()
	cveIDs := make([]string, 0, len(cves))
	for _, value := range cves {
		cveIDs = append(cveIDs, util.CreateLink(strings.ToUpper(value), fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", value)))
	}
	if len(cveIDs) > 0 {
		rows = append(rows, []string{"CVE-ID", strings.Join(cveIDs, ",")})
	}

	return rows
}

func lineBreakToHTML(text string) string {
	return strings.ReplaceAll(text, "\n", "<br>")
}
