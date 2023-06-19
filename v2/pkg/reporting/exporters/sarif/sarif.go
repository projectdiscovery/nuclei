package sarif

import (
	"fmt"
	"math"
	"os"
	"path"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/sarif"
)

// Exporter is an exporter for nuclei sarif output format.
type Exporter struct {
	sarif   *sarif.Report
	mutex   *sync.Mutex
	rulemap map[string]*int // contains rule-id && ruleIndex
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
		rulemap: map[string]*int{},
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
		FullName:        "Nuclei v" + config.Version,
		SemanticVersion: "v" + config.Version,
		DownloadURI:     "https://github.com/projectdiscovery/nuclei/releases",
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
		CommandLine:   os.Args[0],
		Arguments:     os.Args[1:],
		ResponseFiles: []sarif.ArtifactLocation{reportLocation},
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
	resultHeader := fmt.Sprintf("%v (%v) found on %v", event.Info.Name, event.TemplateID, event.Host)
	resultLevel, vulnRating := exporter.getSeverity(severity)

	// Extra metadata if generated sarif is uploaded to GitHub security page
	ghMeta := map[string]interface{}{}
	ghMeta["tags"] = []string{"security"}
	ghMeta["security-severity"] = vulnRating

	// rule contain details of template
	rule := sarif.ReportingDescriptor{
		Id:   event.TemplateID,
		Name: event.Info.Name,
		FullDescription: &sarif.MultiformatMessageString{
			// Points to template URL
			Text: event.Info.Description + "\nMore details at\n" + event.TemplateURL + "\n",
		},
		Properties: ghMeta,
	}

	// GitHub Uses ShortDescription as title
	if event.Info.Description != "" {
		rule.ShortDescription = &sarif.MultiformatMessageString{
			Text: resultHeader,
		}
	}

	// If rule is added
	ruleIndex := int(math.Max(0, float64(len(exporter.rules)-1)))
	if exporter.rulemap[rule.Id] == nil {
		exporter.rulemap[rule.Id] = &ruleIndex
		exporter.rules = append(exporter.rules, rule)
	} else {
		ruleIndex = *exporter.rulemap[rule.Id]
	}

	// vulnerability target/location
	location := sarif.Location{
		Message: &sarif.Message{
			Text: path.Join(event.Host, event.Path),
		},
		PhysicalLocation: sarif.PhysicalLocation{
			ArtifactLocation: sarif.ArtifactLocation{
				// GitHub only accepts file:// protocol and local & relative files only
				// to avoid errors // is used which also translates to file according to specification
				Uri: "/" + event.Path,
				Description: &sarif.Message{
					Text: path.Join(event.Host, event.Path),
				},
			},
		},
	}

	// vulnerability report/result
	result := &sarif.Result{
		RuleId:    rule.Id,
		RuleIndex: ruleIndex,
		Level:     resultLevel,
		Kind:      sarif.Open,
		Message: &sarif.Message{
			Text: resultHeader,
		},
		Locations: []sarif.Location{location},
		Rule: sarif.ReportingDescriptorReference{
			Id: rule.Id,
		},
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

	bin, err := exporter.sarif.Export()
	if err != nil {
		return errors.Wrap(err, "failed to generate sarif report")
	}
	if err := os.WriteFile(exporter.options.File, bin, 0644); err != nil {
		return errors.Wrap(err, "failed to create sarif file")
	}

	return nil
}
