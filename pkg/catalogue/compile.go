package catalogue

import (
	"github.com/projectdiscovery/gologger"
)

// readInputPaths reads initial input after performing exclusions, etc.
func (c *Catalogue) readInputPaths(templates, excludes []string) ([]string, error) {
	var results []string
	for _, template := range templates {
		includes, err := c.GetTemplatePath(template)
		if err != nil {
			gologger.Verbosef("Could not get templates for %s: %s\n", template, err)
			continue
		}
		results = append(results, includes...)
	}

	var allExcludes []string
	for _, excluded := range excludes {
		exclude, err := c.GetTemplatePath(excluded)
		if err != nil {
			gologger.Verbosef("Could not get excluded templates for %s: %s\n", excluded, err)
			continue
		}
		allExcludes = append(allExcludes, exclude...)
	}
	return c.ignoreFilesWithExcludes(results, allExcludes), nil
}

// compileInputPaths compiles a list of input paths into a compact structure.
func (c *Catalogue) compileInputPaths() []*CompiledInput {
	compiledInput := make([]*CompiledInput, 0, len(c.inputFiles))
	for _, template := range c.inputFiles {
		input, err := ReadInput(template)
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
