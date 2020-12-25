package workflows

import "github.com/projectdiscovery/nuclei/v2/pkg/protocols"

// Workflow is a workflow to execute with chained requests, etc.
type Workflow struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info map[string]string `yaml:"info"`
	// Workflows is a yaml based workflow declaration code.
	Workflows []*WorkflowTemplate `yaml:"workflows"`

	path string
}

// WorkflowTemplate is a template to be ran as part of a workflow
type WorkflowTemplate struct {
	// Template is the template to run
	Template string `yaml:"template"`
	// Matchers perform name based matching to run subtemplates for a workflow.
	Matchers []*Matcher `yaml:"matchers"`
	// Subtemplates are ran if the template matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates"`

	executer protocols.Executer
}

// Matcher performs conditional matching on the workflow template results.
type Matcher struct {
	// Name is the name of the item to match.
	Name string `yaml:"name"`
	// Subtemplates are ran if the name of matcher matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates"`
}

// GetPath of the workflow
func (w *Workflow) GetPath() string {
	return w.path
}
