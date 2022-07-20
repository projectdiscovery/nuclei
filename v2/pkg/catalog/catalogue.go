package catalog

// Catalog is a catalog storage implementations
type Catalog interface {
	// ResolvePath resolves the path to an absolute one in various ways.
	//
	// It checks if the filename is an absolute path, looks in the current directory
	// or checking the nuclei templates directory. If a second path is given,
	// it also tries to find paths relative to that second path.
	ResolvePath(templateName, second string) (string, error)
	// GetTemplatePath parses the specified input template path and returns a compiled
	// list of finished absolute paths to the templates evaluating any glob patterns
	// or folders provided as in.
	GetTemplatePath(target string) ([]string, error)
	// GetTemplatesPath returns a list of absolute paths for the provided template list.
	GetTemplatesPath(definitions []string) []string
}

// DiskCatalog is a template catalog helper implementation based on disk
type DiskCatalog struct {
	templatesDirectory string
}

// NewDisk creates a new Catalog structure using provided input items
// using disk based items
func NewDisk(directory string) *DiskCatalog {
	catalog := &DiskCatalog{templatesDirectory: directory}
	return catalog
}
