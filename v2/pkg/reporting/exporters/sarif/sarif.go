package sarif

import (
	"bytes"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

type Exporter struct {
	sarif *sarif.Report
	run   *sarif.Run
	mutex *sync.Mutex

	home    string
	options *Options
}

// Options contains the configuration options for sarif exporter client
type Options struct {
	// File is the file to export found sarif result to
	File string `yaml:"file"`
}

// New creates a new disk exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, errors.Wrap(err, "could not create sarif exporter")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Wrap(err, "could not get home dir")
	}
	templatePath := path.Join(home, "nuclei-templates")

	run := sarif.NewRun("nuclei", "https://github.com/projectdiscovery/nuclei")
	return &Exporter{options: options, home: templatePath, sarif: report, run: run, mutex: &sync.Mutex{}}, nil
}

// Export exports a passed result event to disk
func (i *Exporter) Export(event *output.ResultEvent) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	templatePath := strings.TrimPrefix(event.TemplatePath, i.home)

	description := getSarifResultMessage(event, templatePath)
	sarifSeverity := getSarifSeverity(event)
	sarifRuleHelpURIs := getSarifRuleHelpURIFromReferences(event)

	var ruleName string
	if s, ok := event.Info["name"]; ok {
		ruleName = s.(string)
	}

	var templateURL string
	if strings.HasPrefix(event.TemplatePath, i.home) {
		templateURL = "https://github.com/projectdiscovery/nuclei-templates/blob/master" + templatePath
	}

	var ruleDescription string
	if d, ok := event.Info["description"]; ok {
		ruleDescription = d.(string)
	}
	builder := &strings.Builder{}
	builder.WriteString(ruleDescription)
	if sarifRuleHelpURIs != "" {
		builder.WriteString("\nReferences: \n")
		builder.WriteString(sarifRuleHelpURIs)
	}
	if templateURL != "" {
		builder.WriteString("\nTemplate URL: ")
		builder.WriteString(templateURL)
	}
	ruleHelp := builder.String()

	_ = i.run.AddRule(event.TemplateID).
		WithDescription(ruleName).
		WithHelp(ruleHelp).
		WithHelpURI(templateURL).
		WithFullDescription(sarif.NewMultiformatMessageString(sarifRuleHelpURIs))

	_ = i.run.AddResult(event.TemplateID).
		WithMessage(sarif.NewMessage().WithText(description)).
		WithLevel(sarifSeverity).
		WithLocation(sarif.NewLocation().WithMessage(sarif.NewMessage().WithText(event.Host)).WithPhysicalLocation(
			sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithUri(event.Type)).
				WithRegion(sarif.NewRegion().WithStartColumn(1).WithStartLine(1).WithEndLine(1).WithEndColumn(1)),
		))
	return nil
}

// getSarifSeverity returns the sarif severity
func getSarifSeverity(event *output.ResultEvent) string {
	var ruleSeverity string
	if s, ok := event.Info["severity"]; ok {
		ruleSeverity = s.(string)
	}

	switch ruleSeverity {
	case "info":
		return "none"
	case "low", "medium":
		return "warning"
	case "high", "critical":
		return "error"
	default:
		return "none"
	}
}

// getSarifRuleHelpURIFromReferences returns the sarif rule help uri
func getSarifRuleHelpURIFromReferences(event *output.ResultEvent) string {
	if d, ok := event.Info["reference"]; ok {
		switch v := d.(type) {
		case string:
			return v
		case []interface{}:
			slice := types.ToStringSlice(v)
			return strings.Join(slice, "\n")
		}
	}
	return ""
}

// getSarifResultMessage gets a sarif result message from event
func getSarifResultMessage(event *output.ResultEvent, templatePath string) string {
	template := format.GetMatchedTemplate(event)
	builder := &bytes.Buffer{}

	builder.WriteString(template)
	builder.WriteString(" matched at ")
	builder.WriteString(event.Host)
	builder.WriteString(" (")
	builder.WriteString(strings.ToUpper(event.Type))
	builder.WriteString(") => ")
	builder.WriteString(event.Matched)

	if len(event.ExtractedResults) > 0 || len(event.Metadata) > 0 {
		if len(event.ExtractedResults) > 0 {
			builder.WriteString(" **Extracted results**:\n\n")
			for _, v := range event.ExtractedResults {
				builder.WriteString("- ")
				builder.WriteString(v)
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
		if len(event.Metadata) > 0 {
			builder.WriteString(" **Metadata**:\n\n")
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
		builder.WriteString("**Interaction Data**\n---\n")
		builder.WriteString(event.Interaction.Protocol)
	}

	builder.WriteString(" To Reproduce - `nuclei -t ")
	builder.WriteString(strings.TrimPrefix(templatePath, "/"))
	builder.WriteString(" -target \"")
	builder.WriteString(event.Host)
	builder.WriteString("\"`")

	data := builder.String()
	return data
}

// Close closes the exporter after operation
func (i *Exporter) Close() error {
	i.sarif.AddRun(i.run)

	file, err := os.Create(i.options.File)
	if err != nil {
		return errors.Wrap(err, "could not create sarif output file")
	}
	defer file.Close()
	return i.sarif.Write(file)
}
