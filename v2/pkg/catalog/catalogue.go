package catalog

// Catalog is a template catalog helper implementation
type Catalog struct {
	// RestrictScope restricts the scope of templates being loaded
	// to the templatesDirectory and does not do lookups on relative paths.
	RestrictScope bool

	templatesDirectory string
}

// New creates a new Catalog structure using provided input items
func New(directory string) *Catalog {
	catalog := &Catalog{templatesDirectory: directory}
	return catalog
}
