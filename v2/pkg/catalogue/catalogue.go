package catalogue

// Catalogue is a template catalouge helper implementation
type Catalogue struct {
	ignoreFiles        []string
	templatesDirectory string
}

// New creates a new catalogue structure using provided input items
func New(directory string) *Catalogue {
	catalogue := &Catalogue{templatesDirectory: directory}
	catalogue.readNucleiIgnoreFile()
	return catalogue
}
