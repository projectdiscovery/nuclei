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
	ID   string
	Info quarks.Info

	// Logic is the logic to be executed for a workflow
	Logic string

	// Templates contains the list of templates loaded for workflow.
	Templates map[string][]*templates.CompiledTemplate
}

// CompileOptions contains the options for workflow compilation
type CompileOptions struct {
	ID       string
	Path     string
	Info     quarks.Info
	Compiler TemplateCompiler
	Resolver quarks.PathResolver
}

// TemplateCompiler is an interface used for compiling templates for workflows
type TemplateCompiler interface {
	// GetTemplatesForWorkflow returns compiled templates for a workflow
	GetTemplatesForWorkflow(templates []string) ([]*templates.CompiledTemplate, error)
}

// Compile compiles a workflow performing all processing structure.
func (t Workflow) Compile(opts CompileOptions) (*CompiledWorkflow, error) {
	result := &CompiledWorkflow{
		ID:        opts.ID,
		Info:      opts.Info,
		Logic:     t.Logic,
		Templates: make(map[string][]*templates.CompiledTemplate, len(t.Variables)),
	}

	for key, value := range t.Variables {
		templates, err := opts.Resolver.GetTemplatePath(value)
		if err != nil {
			return nil, errors.Wrap(err, "could not get templates for workflow")
		}
		compiled, err := opts.Compiler.GetTemplatesForWorkflow(templates)
		if err != nil {
			return nil, errors.Wrapf(err, "could not compile template for workflow: %s", value)
		}
		result.Templates[key] = compiled
	}
	return result, nil
}
