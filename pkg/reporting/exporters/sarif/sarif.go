package sarif

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/sarif"
)

const (
	maxDetailValueLength   = 400
	maxExtractedValues     = 5
	maxRuleReferences      = 8
	fallbackTemplateRuleID = "nuclei-template"
)

// Exporter is an exporter for nuclei sarif output format.
type Exporter struct {
	sarif   *sarif.Report
	mutex   *sync.Mutex
	rulemap map[string]int // contains rule-id && ruleIndex
	rules   []sarif.ReportingDescriptor
	options *Options
}

// Options contains the configuration options for sarif exporter client
type Options struct {
	// File is the file to export found sarif result to
	File string `yaml:"file"`
}

// New creates a new sarif exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	report := sarif.NewReport()
	exporter := &Exporter{
		sarif:   report,
		mutex:   &sync.Mutex{},
		rules:   []sarif.ReportingDescriptor{},
		rulemap: map[string]int{},
		options: options,
	}
	return exporter, nil
}

// addToolDetails adds details of static analysis tool (i.e nuclei)
func (exporter *Exporter) addToolDetails() {
	driver := sarif.ToolComponent{
		Name:         "Nuclei",
		Organization: "ProjectDiscovery",
		Product:      "Nuclei",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "Fast and Customizable Vulnerability Scanner",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Fast and customizable vulnerability scanner based on simple YAML based DSL",
		},
		FullName:        "Nuclei " + config.Version,
		SemanticVersion: config.Version,
		DownloadUri:     "https://github.com/projectdiscovery/nuclei/releases",
		InformationUri:  "https://github.com/projectdiscovery/nuclei/releases",
		Rules:           exporter.rules,
	}
	exporter.sarif.RegisterTool(driver)

	reportLocation := sarif.ArtifactLocation{
		Uri: "file:///" + exporter.options.File,
		Description: &sarif.Message{
			Text: "Nuclei Sarif Report",
		},
	}

	invocation := sarif.Invocation{
		CommandLine:         os.Args[0],
		Arguments:           os.Args[1:],
		ResponseFiles:       []sarif.ArtifactLocation{reportLocation},
		ExecutionSuccessful: true,
	}
	exporter.sarif.RegisterToolInvocation(invocation)
}

// getSeverity in terms of sarif
func (exporter *Exporter) getSeverity(severity string) (sarif.Level, string) {
	switch severity {
	case "critical":
		return sarif.Error, "9.4"
	case "high":
		return sarif.Error, "8"
	case "medium":
		return sarif.Note, "5"
	case "low":
		return sarif.Note, "2"
	case "info":
		return sarif.None, "1"
	}

	return sarif.None, "9.5"
}

// Export exports a passed result event to sarif structure
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	severity := event.Info.SeverityHolder.Severity.String()
	ruleID := normalizeValue(event.TemplateID)
	if ruleID == "" {
		ruleID = fallbackTemplateRuleID
	}
	ruleName := normalizeValue(event.Info.Name)
	if ruleName == "" {
		ruleName = ruleID
	}
	resultTarget := getResultTarget(event)
	resultHeader := fmt.Sprintf("%s (%s) found on %s", ruleName, ruleID, event.URL)
	resultLevel, vulnRating := exporter.getSeverity(severity)
	if classification := event.Info.Classification; classification != nil && classification.CVSSScore > 0 {
		vulnRating = fmt.Sprintf("%.1f", classification.CVSSScore)
	}

	// Extra metadata if generated sarif is uploaded to GitHub security page
	ghMeta := map[string]interface{}{
		"tags":              buildRuleTags(event),
		"security-severity": vulnRating,
	}

	// rule contain details of template
	rule := sarif.ReportingDescriptor{
		Id:      ruleID,
		Name:    ruleName,
		HelpUri: normalizeValue(event.TemplateURL),
		ShortDescription: &sarif.MultiformatMessageString{
			Text: ruleName,
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: buildRuleDescription(event, ruleName),
		},
		Help: &sarif.MultiformatMessageString{
			Text:     buildRuleHelpText(event),
			Markdown: buildRuleHelpMarkdown(event, ruleName),
		},
		Properties: ghMeta,
	}

	// Add rule once and keep stable rule indices.
	ruleIndex, found := exporter.rulemap[ruleID]
	if !found {
		ruleIndex = len(exporter.rules)
		exporter.rulemap[ruleID] = ruleIndex
		exporter.rules = append(exporter.rules, rule)
	}

	location := buildLocation(event, resultTarget)

	// vulnerability report/result
	result := &sarif.Result{
		RuleId:    ruleID,
		RuleIndex: ruleIndex,
		Level:     resultLevel,
		Kind:      sarif.Open,
		Message:   buildResultMessage(event, resultHeader, ruleID),
		Locations: []sarif.Location{location},
		Rule: sarif.ReportingDescriptorReference{
			Id: ruleID,
		},
		Properties: buildResultProperties(event, resultTarget),
	}

	exporter.sarif.RegisterResult(*result)

	return nil

}

// Close Writes data and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if len(exporter.rules) == 0 {
		// no output if there are no results
		return nil
	}
	// links results and rules/templates
	exporter.addToolDetails()

	bin, err := exporter.sarif.ExportWithOptions(
		sarif.WithNormalization(true),
		sarif.WithEmptyObjectPruning(true),
	)
	if err != nil {
		return errors.Wrap(err, "failed to generate sarif report")
	}
	if err := os.WriteFile(exporter.options.File, bin, 0644); err != nil {
		return errors.Wrap(err, "failed to create sarif file")
	}

	return nil
}

func buildRuleDescription(event *output.ResultEvent, ruleName string) string {
	description := normalizeValue(event.Info.Description)
	if description == "" {
		description = ruleName
	}
	if templateURL := normalizeValue(event.TemplateURL); templateURL != "" {
		description += "\nMore details at\n" + templateURL
	}
	return description
}

func buildRuleHelpText(event *output.ResultEvent) string {
	sections := []string{}

	if description := normalizeValue(event.Info.Description); description != "" {
		sections = append(sections, description)
	}
	if impact := normalizeValue(event.Info.Impact); impact != "" {
		sections = append(sections, "Impact: "+impact)
	}
	if remediation := normalizeValue(event.Info.Remediation); remediation != "" {
		sections = append(sections, "Remediation: "+remediation)
	}
	if templatePath := normalizeValue(firstNonEmpty(event.Template, event.TemplatePath)); templatePath != "" {
		sections = append(sections, "Nuclei Template: "+templatePath)
	}
	if refs := getReferences(event); len(refs) > 0 {
		sections = append(sections, "References: "+strings.Join(refs, ", "))
	}
	if templateURL := normalizeValue(event.TemplateURL); templateURL != "" {
		sections = append(sections, "More details: "+templateURL)
	}

	if len(sections) == 0 {
		return "No additional template metadata was provided by the scanner."
	}

	return strings.Join(sections, "\n")
}

func buildRuleHelpMarkdown(event *output.ResultEvent, ruleName string) string {
	lines := []string{fmt.Sprintf("### %s", ruleName), ""}

	if description := normalizeValue(event.Info.Description); description != "" {
		lines = append(lines, description, "")
	}
	if impact := normalizeValue(event.Info.Impact); impact != "" {
		lines = append(lines, fmt.Sprintf("- **Impact:** %s", impact))
	}
	if remediation := normalizeValue(event.Info.Remediation); remediation != "" {
		lines = append(lines, fmt.Sprintf("- **Remediation:** %s", remediation))
	}
	if templatePath := normalizeValue(firstNonEmpty(event.Template, event.TemplatePath)); templatePath != "" {
		lines = append(lines, fmt.Sprintf("- **Nuclei Template:** %s", templatePath))
	}

	if refs := getReferences(event); len(refs) > 0 {
		lines = append(lines, "", "**References**")
		for _, ref := range refs {
			lines = append(lines, "- "+ref)
		}
	}

	if templateURL := normalizeValue(event.TemplateURL); templateURL != "" {
		lines = append(lines, "", "More details: "+templateURL)
	}

	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func buildResultMessage(event *output.ResultEvent, resultHeader, ruleID string) *sarif.Message {
	detailLines := []string{}
	target := getResultTarget(event)
	addDetail(&detailLines, "Target", target)
	if matched := normalizeAndTruncate(event.Matched, maxDetailValueLength); matched != "" && matched != target {
		addDetail(&detailLines, "Matched At", matched)
	}
	if baseURL := normalizeAndTruncate(event.URL, maxDetailValueLength); baseURL != "" {
		addDetail(&detailLines, "Base URL", baseURL)
	}
	if host := normalizeAndTruncate(event.Host, maxDetailValueLength); host != "" && host != target {
		addDetail(&detailLines, "Host", host)
	}
	addDetail(&detailLines, "IP", event.IP)
	addDetail(&detailLines, "Protocol", event.Type)
	addDetail(&detailLines, "Matcher", event.MatcherName)
	addDetail(&detailLines, "Extractor", event.ExtractorName)
	addDetail(&detailLines, "Nuclei Template", ruleID)
	if templatePath := normalizeAndTruncate(firstNonEmpty(event.Template, event.TemplatePath), maxDetailValueLength); templatePath != "" {
		addDetail(&detailLines, "Nuclei Template Path", templatePath)
	}
	if extracted := formatExtractedResults(event.ExtractedResults); extracted != "" {
		addDetail(&detailLines, "Extracted Results", extracted)
	}

	reproduction := normalizeAndTruncate(event.CURLCommand, maxDetailValueLength*2)

	text := resultHeader
	if len(detailLines) > 0 {
		text += "\n" + strings.Join(detailLines, "\n")
	}
	if reproduction != "" {
		text += "\nReproduce:\n"
		text += "```bash\n" + reproduction + "\n```"
	}

	markdownLines := []string{resultHeader}
	if len(detailLines) > 0 {
		markdownLines = append(markdownLines, "", "\n**Triage Details**:")
		for _, detail := range detailLines {
			parts := strings.SplitN(detail, ": ", 2)
			if len(parts) == 2 {
				markdownLines = append(markdownLines, fmt.Sprintf("- **%s:** %s", parts[0], parts[1]))
				continue
			}
			markdownLines = append(markdownLines, "- "+detail)
		}
	}
	if reproduction != "" {
		markdownLines = append(markdownLines, "", "\n**Reproduce**:", "```bash", reproduction, "```")
	}

	return &sarif.Message{
		Text:     text,
		Markdown: strings.Join(markdownLines, "\n"),
	}
}

func buildResultProperties(event *output.ResultEvent, target string) map[string]interface{} {
	properties := map[string]interface{}{}

	if normalizedTarget := normalizeAndTruncate(target, maxDetailValueLength); normalizedTarget != "" {
		properties["target"] = normalizedTarget
	}
	if matched := normalizeAndTruncate(event.Matched, maxDetailValueLength); matched != "" {
		properties["matched-at"] = matched
	}
	if matcher := normalizeAndTruncate(event.MatcherName, maxDetailValueLength); matcher != "" {
		properties["matcher"] = matcher
	}
	if extractor := normalizeAndTruncate(event.ExtractorName, maxDetailValueLength); extractor != "" {
		properties["extractor"] = extractor
	}
	if len(event.ExtractedResults) > 0 {
		trimmed := make([]string, 0, maxExtractedValues)
		for i, value := range event.ExtractedResults {
			if i >= maxExtractedValues {
				break
			}
			if normalized := normalizeAndTruncate(value, maxDetailValueLength); normalized != "" {
				trimmed = append(trimmed, normalized)
			}
		}
		if len(trimmed) > 0 {
			properties["extracted-results"] = trimmed
		}
	}
	if templatePath := normalizeAndTruncate(firstNonEmpty(event.Template, event.TemplatePath), maxDetailValueLength); templatePath != "" {
		properties["template-path"] = templatePath
	}

	if len(properties) == 0 {
		return nil
	}

	return properties
}

func buildLocation(event *output.ResultEvent, resultTarget string) sarif.Location {
	location := sarif.Location{
		Message: &sarif.Message{
			Text: resultTarget,
		},
		PhysicalLocation: sarif.PhysicalLocation{
			ArtifactLocation: sarif.ArtifactLocation{
				Uri: buildArtifactURI(event),
				Description: &sarif.Message{
					Text: resultTarget,
				},
			},
		},
	}

	if line := firstPositiveLine(event.Lines); line > 0 {
		location.PhysicalLocation.Region = &sarif.Region{StartLine: line}
	}

	return location
}

func buildArtifactURI(event *output.ResultEvent) string {
	if template := normalizePath(firstNonEmpty(event.Template, event.TemplatePath)); template != "" {
		if idx := strings.Index(template, "/nuclei-templates/"); idx >= 0 {
			return strings.TrimLeft(template[idx+len("/nuclei-templates/"):], "/")
		}
		return strings.TrimLeft(template, "/")
	}

	if targetPath := normalizePath(event.Path); targetPath != "" && targetPath != "/" && targetPath != "." {
		return strings.TrimLeft(targetPath, "/")
	}

	if templateID := normalizeValue(event.TemplateID); templateID != "" {
		return path.Join("nuclei-results", templateID+".txt")
	}

	return "nuclei-results/result.txt"
}

func buildRuleTags(event *output.ResultEvent) []string {
	tags := []string{"security"}
	for _, tag := range event.Info.Tags.ToSlice() {
		normalizedTag := normalizeValue(tag)
		if normalizedTag == "" {
			continue
		}
		tags = appendIfMissing(tags, normalizedTag)
	}

	if classification := event.Info.Classification; classification != nil {
		for _, cwe := range classification.CWEID.ToSlice() {
			if cweTag := buildCWETag(cwe); cweTag != "" {
				tags = appendIfMissing(tags, cweTag)
			}
		}
	}

	return tags
}

func getReferences(event *output.ResultEvent) []string {
	if event.Info.Reference == nil {
		return nil
	}
	references := event.Info.Reference.ToSlice()
	if len(references) == 0 {
		return nil
	}

	output := make([]string, 0, min(len(references), maxRuleReferences))
	for i, reference := range references {
		if i >= maxRuleReferences {
			break
		}
		if normalizedRef := normalizeAndTruncate(reference, maxDetailValueLength); normalizedRef != "" {
			output = append(output, normalizedRef)
		}
	}

	return output
}

func getResultTarget(event *output.ResultEvent) string {
	for _, value := range []string{event.Matched, event.URL, event.Host, event.Path} {
		if normalized := normalizeAndTruncate(value, maxDetailValueLength); normalized != "" {
			return normalized
		}
	}
	return "unknown target"
}

func formatExtractedResults(values []string) string {
	if len(values) == 0 {
		return ""
	}

	trimmed := make([]string, 0, maxExtractedValues)
	for i, value := range values {
		if i >= maxExtractedValues {
			break
		}
		if normalized := normalizeAndTruncate(value, maxDetailValueLength); normalized != "" {
			trimmed = append(trimmed, normalized)
		}
	}

	if len(trimmed) == 0 {
		return ""
	}

	if len(values) > len(trimmed) {
		trimmed = append(trimmed, fmt.Sprintf("... and %d more", len(values)-len(trimmed)))
	}

	return strings.Join(trimmed, ", ")
}

func firstPositiveLine(lines []int) int {
	for _, line := range lines {
		if line > 0 {
			return line
		}
	}
	return 0
}

func addDetail(lines *[]string, label, value string) {
	normalizedValue := normalizeAndTruncate(value, maxDetailValueLength)
	if normalizedValue == "" {
		return
	}
	*lines = append(*lines, fmt.Sprintf("%s: %s", label, normalizedValue))
}

func normalizeAndTruncate(value string, limit int) string {
	normalized := normalizeValue(value)
	if normalized == "" {
		return ""
	}
	if limit > 0 && len(normalized) > limit {
		return normalized[:limit-3] + "..."
	}
	return normalized
}

func normalizeValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

func normalizePath(value string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if normalized == "" {
		return ""
	}
	return path.Clean(normalized)
}

func appendIfMissing(values []string, candidate string) []string {
	for _, existing := range values {
		if existing == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func buildCWETag(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	normalized = strings.TrimPrefix(normalized, "cwe-")
	digitsOnly := strings.Builder{}
	for _, char := range normalized {
		if char >= '0' && char <= '9' {
			digitsOnly.WriteRune(char)
		}
	}
	if digitsOnly.Len() == 0 {
		return ""
	}
	return "external/cwe/cwe-" + digitsOnly.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
