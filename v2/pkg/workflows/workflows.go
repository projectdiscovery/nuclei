package workflows

import "github.com/projectdiscovery/nuclei/v2/pkg/protocols"

// Workflow is a workflow to execute with chained requests, etc.
type Workflow struct {
	// description: |
	//   Workflows is a list of workflows to execute for a template.
	Workflows []*WorkflowTemplate `yaml:"workflows,omitempty"`

	Options *protocols.ExecuterOptions
}

// WorkflowTemplate is a template to be ran as part of a workflow
type WorkflowTemplate struct {
	// description: |
	//   Template is a single template or directory to execute as part of workflow.
	// examples:
	//   - name: A single template
	//     value: "\"dns/worksites-detection.yaml\""
	//   - name: A template directory
	//     value: "\"misconfigurations/aem\""
	Template string `yaml:"template,omitempty"`
	// description: |
	//    Tags to run templates based on.
	Tags string `yaml:"tags,omitempty"`
	// description: |
	//    Matchers perform name based matching to run subtemplates for a workflow.
	Matchers []*Matcher `yaml:"matchers,omitempty"`
	// description: |
	//    Subtemplates are ran if the `template` field Template matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates,omitempty"`
	// Executers perform the actual execution for the workflow template
	Executers []*ProtocolExecuterPair
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
	Name string `yaml:"name,omitempty"`
	// description: |
	//    Subtemplates are ran if the name of matcher matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates,omitempty"`
}
