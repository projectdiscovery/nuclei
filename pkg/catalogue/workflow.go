package catalogue

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/templates"
)

// GetTemplatesForWorkflow returns compiled templates for a workflow
func (c *Catalogue) GetTemplatesForWorkflow(inputs []string) ([]*templates.CompiledTemplate, error) {
	compiledInput := make([]*templates.CompiledTemplate, 0, len(inputs))
	for _, template := range inputs {
		input, err := ReadInput(template)
		if err != nil {
			return nil, errors.Wrapf(err, "could not read template: %s", template)
		}
		compiled, err := input.Compile(c, template)
		if err != nil {
			return nil, errors.Wrapf(err, "could not compile template: %s", template)
		}
		if compiled.Type != TemplateInputType {
			continue
		}
		compiledInput = append(compiledInput, compiled.CompiledTemplate)
	}
	return compiledInput, nil
}
