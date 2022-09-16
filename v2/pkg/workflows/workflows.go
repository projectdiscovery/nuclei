package workflows

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
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
	//    Name is the name of the items to match.
	Name stringslice.StringSlice `yaml:"names,omitempty" jsonschema:"title=name of items to match,description=Name of items to match"`
	// description: |
	//   Condition is the optional condition between names. By default,
	//   the condition is assumed to be OR.
	// values:
	//   - "and"
	//   - "or"
	Condition string `yaml:"condition,omitempty" jsonschema:"title=condition between names,description=Condition between the names,enum=and,enum=or"`
	// description: |
	//    Subtemplates are run if the name of matcher matches.
	Subtemplates []*WorkflowTemplate `yaml:"subtemplates,omitempty" jsonschema:"title=templates to run after match,description=Templates to run after match"`

	condition ConditionType
}

// ConditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// ConditionTypes is a table for conversion of condition type from string.
var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}

// Compile compiles the matcher for workflow
func (matcher *Matcher) Compile() error {
	var ok bool
	if matcher.Condition != "" {
		matcher.condition, ok = ConditionTypes[matcher.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", matcher.Condition)
		}
	} else {
		matcher.condition = ORCondition
	}
	return nil
}

// Match matches a name for matcher names or name
func (matcher *Matcher) Match(result *operators.Result) bool {
	names := matcher.Name.ToSlice()

	if len(names) == 0 {
		return false
	}

	for i, name := range names {
		_, matchOK := result.Matches[name]
		_, extractOK := result.Extracts[name]

		if !matchOK && !extractOK {
			if matcher.condition == ANDCondition {
				return false
			} else if matcher.condition == ORCondition {
				continue
			}
		}
		if matcher.condition == ORCondition {
			return true
		} else if len(names)-1 == i {
			return true
		}
	}
	return false
}
