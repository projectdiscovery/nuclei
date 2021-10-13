package sarif

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Exporter is an exporter for nuclei sarif output format.
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

// New creates a new sarif exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, errors.Wrap(err, "could not create sarif exporter")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Wrap(err, "could not get home dir")
	}
	templatePath := filepath.Join(home, "nuclei-templates")

	run := sarif.NewRun("nuclei", "https://github.com/projectdiscovery/nuclei")
	return &Exporter{options: options, home: templatePath, sarif: report, run: run, mutex: &sync.Mutex{}}, nil
}

// Export exports a passed result event to sarif structure
func (i *Exporter) Export(event *output.ResultEvent) error {
	templatePath := strings.TrimPrefix(event.TemplatePath, i.home)

	h := sha1.New()
	_, _ = h.Write([]byte(event.Host))
	templateID := event.TemplateID + "-" + hex.EncodeToString(h.Sum(nil))

	fullDescription := format.MarkdownDescription(event)
	sarifSeverity := getSarifSeverity(event)

	var ruleName string
	if utils.IsNotBlank(event.Info.Name) {
		ruleName = event.Info.Name
	}

	var templateURL string
	if strings.HasPrefix(event.TemplatePath, i.home) {
		templateURL = "https://github.com/projectdiscovery/nuclei-templates/blob/master" + templatePath
	} else {
		templateURL = "https://github.com/projectdiscovery/nuclei-templates"
	}

	var ruleDescription string
	if utils.IsNotBlank(event.Info.Description) {
		ruleDescription = event.Info.Description
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	_ = i.run.AddRule(templateID).
		WithDescription(ruleName).
		WithHelp(fullDescription).
		WithHelpURI(templateURL).
		WithFullDescription(sarif.NewMultiformatMessageString(ruleDescription))
	result := i.run.AddResult(templateID).
		WithMessage(sarif.NewMessage().WithText(event.Host)).
		WithLevel(sarifSeverity)

		// Also write file match metadata to file
	if event.Type == "file" && (event.FileToIndexPosition != nil && len(event.FileToIndexPosition) > 0) {
		for file, line := range event.FileToIndexPosition {
			result.WithLocation(sarif.NewLocation().WithMessage(sarif.NewMessage().WithText(ruleName)).WithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewArtifactLocation().WithUri(file)).
					WithRegion(sarif.NewRegion().WithStartColumn(1).WithStartLine(line).WithEndLine(line).WithEndColumn(32)),
			))
		}
	} else {
		result.WithLocation(sarif.NewLocation().WithMessage(sarif.NewMessage().WithText(event.Host)).WithPhysicalLocation(
			sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithUri("README.md")).
				WithRegion(sarif.NewRegion().WithStartColumn(1).WithStartLine(1).WithEndLine(1).WithEndColumn(1)),
		))
	}
	return nil
}

// getSarifSeverity returns the sarif severity
func getSarifSeverity(event *output.ResultEvent) string {
	switch event.Info.SeverityHolder.Severity {
	case severity.Info:
		return "note"
	case severity.Low, severity.Medium:
		return "warning"
	case severity.High, severity.Critical:
		return "error"
	default:
		return "note"
	}
}

// Close closes the exporter after operation
func (i *Exporter) Close() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	i.sarif.AddRun(i.run)
	if len(i.run.Results) == 0 {
		return nil // do not write when no results
	}
	file, err := os.Create(i.options.File)
	if err != nil {
		return errors.Wrap(err, "could not create sarif output file")
	}
	defer file.Close()
	return i.sarif.Write(file)
}
