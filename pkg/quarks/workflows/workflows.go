package workflows

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/templates"
)

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
func (t Workflow) Compile(resolver quarks.PathResolver, path string) (*CompiledWorkflow, error) {
	compiled := &CompiledWorkflow{
		Logic:     t.Logic,
		Templates: make(map[string][]*templates.CompiledTemplate, len(t.Variables)),
	}

	for key, value := range t.Variables {
		templates, err := resolver.GetTemplatePath(value)
		if err != nil {
			return nil, errors.Wrap(err, "could not get templates for workflow")
		}
		for _, template := range templates {
			//	input, err := input.Read(template)
			//	if err != nil {
			//		continue
			//	}
			//
			//	compiledTemplate, err := i.Template.Compile(catalogue, path)
			//	if err != nil {
			//		return nil, errors.Wrap(err, "could not compile template")
			//	}
			//	compiled.CompiledTemplate = compiledTemplate
		}
		_ = key
		_ = value
	}
	return compiled, nil
}
