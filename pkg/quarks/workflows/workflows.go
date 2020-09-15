package workflows

import "github.com/projectdiscovery/nuclei/v2/pkg/quarks/templates"

// Workflow is a workflow structure parsed from a yaml file
type Workflow struct {
	// Logic contains the workflow logic to execute
	Logic string `yaml:"logic"`
	// Variables contains the templates in form of variables for execution
	Variables map[string]string `yaml:"variables"`
}

// CompiledWorkflow is the compiled workflow parsed from yaml file.
type CompiledWorkflow struct {
	// Logic is the logic to be executed for a workflow
	Logic string

	// Templates contains the list of templates loaded for workflow.
	Templates map[string][]*templates.CompiledTemplate
}

// Compile compiles a workflow performing all processing structure.
func (t *Workflow) Compile() (*CompiledWorkflow, error) {
	return nil, nil
}
