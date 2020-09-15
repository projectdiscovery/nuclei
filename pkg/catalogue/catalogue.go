package catalogue

// Catalogue is an inventory of inputs loaded for execution.
type Catalogue struct {
	ignoreFiles []string

	templatesDirectory string
}

// New creates a new catalogue structure using provided input items
func New(directory string, templates, exclude []string) (*Catalogue, error) {
	catalogue := &Catalogue{templatesDirectory: directory}
	catalogue.readNucleiIgnoreFile()

	//	for _, template := range templates {
	//
	//	}
	return catalogue, nil
}
