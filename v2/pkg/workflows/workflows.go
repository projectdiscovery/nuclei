package workflows

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Workflow is a workflow to execute with chained requests, etc.
type Workflow struct {
	// description: |
	//   Workflows is a list of workflows to execute for a template.
	Workflows []*WorkflowTemplate `yaml:"workflows,omitempty" jsonschema:"title=list of workflows to execute,description=List of workflows to execute for template"`

	Options *protocols.ExecuterOptions `yaml:"-"`
}

// WorkflowTemplate is a template to be run as part of a workflow
type WorkflowTemplate struct {
	// description: |
	//   Template is a single template or directory to execute as part of workflow.
	// examples:
	//   - name: A single template
	//     value: "\"dns/worksites-detection.yaml\""
	//   - name: A template directory
	//     value: "\"misconfigurations/aem\""
	Template string `yaml:"template,omitempty" jsonschema:"title=template/directory to execute,description=Template or directory to execute as part of workflow"`
	// description: |
	//    CaptureValues enables capturing of values from ran templates
	CaptureValues bool `yaml:"capture-values,omitempty" jsonschema:"title=capture values from templates,description=Enable capturing of values from templates"`
	// description: |
	//    Tags to run templates based on.
	Tags stringslice.StringSlice `yaml:"tags,omitempty" jsonschema:"title=tags to execute,description=Tags to run template based on"`
	// description: |
	//    Matchers perform name based matching to run subtemplates for a workflow.
	Matchers []*Matcher `yaml:"matchers,omitempty" jsonschema:"title=name based template result matchers,description=Matchers perform name based matching to run subtemplates for a workflow"`
	// description: |
	//    Subtemplates are run if the `template` field Template matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates,omitempty" jsonschema:"title=subtemplate based result matchers,description=Subtemplates are ran if the template field Template matches"`
	// Executers perform the actual execution for the workflow template
	Executers []*ProtocolExecuterPair `yaml:"-"`
}

// ProtocolExecuterPair is a pair of protocol executer and its options
type ProtocolExecuterPair struct {
	Executer protocols.Executer
	Options  *protocols.ExecuterOptions
}

// Matcher performs conditional matching on the workflow template results.
type Matcher struct {
	// description: |
	//    Name is the name of the item to match.
	Name string `yaml:"name,omitempty" jsonschema:"title=name of item to match,description=Name of item to match"`
	// description: |
	//    Subtemplates are run if the name of matcher matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates,omitempty" jsonschema:"title=templates to run after match,description=Templates to run after match"`
}
