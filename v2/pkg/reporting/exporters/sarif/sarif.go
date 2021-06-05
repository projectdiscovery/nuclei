package sarif

import (
	"os"
	"sync"

	"github.com/owenrumney/go-sarif/sarif"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
)

type Exporter struct {
	sarif *sarif.Report
	run   *sarif.Run
	mutex *sync.Mutex

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
	run := sarif.NewRun("nuclei", "https://github.com/projectdiscovery/nuclei")
	return &Exporter{options: options, sarif: report, run: run, mutex: &sync.Mutex{}}, nil
}

// Export exports a passed result event to disk
func (i *Exporter) Export(event *output.ResultEvent) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	description := format.MarkdownDescription(event)

	var ruleDescription string
	if d, ok := event.Info["description"]; ok {
		ruleDescription = d.(string)
	}
	var ruleSeverity string
	if s, ok := event.Info["severity"]; ok {
		ruleSeverity = s.(string)
	}
	var ruleName string
	if s, ok := event.Info["name"]; ok {
		ruleName = s.(string)
	}

	var sarifSeverity string
	switch ruleSeverity {
	case "info":
		sarifSeverity = "none"
	case "low", "medium":
		sarifSeverity = "warning"
	case "high", "critical":
		sarifSeverity = "error"
	}
	_ = i.run.AddRule(event.TemplateID).
		WithDescription(ruleName).
		WithFullDescription(sarif.NewMultiformatMessageString(ruleDescription)).
		WithHelp(ruleDescription)
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
