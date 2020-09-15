package catalogue

// Catalogue is an inventory of inputs loaded for execution.
type Catalogue struct {
	compiledInput []*CompiledInput
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
	catalogue.compiledInput = catalogue.compileInputPaths(templates)
	return catalogue, nil
}
