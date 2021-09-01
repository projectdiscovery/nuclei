package catalog

// Catalog is a template catalog helper implementation
type Catalog struct {
	templatesDirectory string
}

// New creates a new Catalog structure using provided input items
func New(directory string) *Catalog {
	catalog := &Catalog{templatesDirectory: directory}
	return catalog
}
