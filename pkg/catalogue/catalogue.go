package catalogue

// Catalogue is an inventory of inputs loaded for execution.
type Catalogue struct {
	compiledInput []*CompiledInput
	inputFiles    []string
	ignoreFiles   []string

	templatesDirectory string
}

// New creates a new catalogue structure using provided input items
func New(directory string, templates, excludes []string) (*Catalogue, error) {
	catalogue := &Catalogue{templatesDirectory: directory}
	catalogue.readNucleiIgnoreFile()

	templates, err := catalogue.readInputPaths(templates, excludes)
	if err != nil {
		return nil, err
	}
	catalogue.inputFiles = templates
	catalogue.compiledInput = catalogue.compileInputPaths()
	return catalogue, nil
}

// GetCompiledInput returns the current compiled input
func (c *Catalogue) GetCompiledInput() []*CompiledInput {
	return c.compiledInput
}

// GetInputFiles returns the current input file catalogue
func (c *Catalogue) GetInputFiles() []string {
	return c.inputFiles
}
