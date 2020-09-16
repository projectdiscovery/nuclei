package catalogue

import "github.com/projectdiscovery/gologger"

// GetTemplatesForWorkflow returns compiled templates for a workflow
func (c *Catalogue) GetTemplatesForWorkflow(templates []string) ([]*CompiledInput, error) {
	compiledInput := make([]*CompiledInput, 0, len(c.inputFiles))
	for _, template := range c.inputFiles {
		input, err := Read(template)
		if err != nil {
			gologger.Verbosef("Could not read template %s: %s\n", template, err)
			continue
		}
		compiled, err := input.Compile(c, template)
		if err != nil {
			gologger.Verbosef("Could not compile template %s: %s\n", template, err)
			continue
		}
		compiledInput = append(compiledInput, compiled)
	}
	return compiledInput
}
