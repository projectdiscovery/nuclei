package catalogue

// Catalogue is an inventory of inputs loaded for execution.
type Catalogue struct {
	templatesDirectory string
}

// New creates a new catalogue structure using provided input items
func New(directory string, templates, exclude []string) (*Catalogue, error) {
	catalogue := &Catalogue{templatesDirectory: directory}

	//	for _, template := range templates {
	//
	//	}
	return catalogue, nil
}
