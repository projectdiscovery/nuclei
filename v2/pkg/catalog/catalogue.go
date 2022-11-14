package catalog

import "io"

// Catalog is a catalog storage implementations
type Catalog interface {
	// OpenFile opens a file and returns an io.ReadCloser to the file.
	// It is used to read template and payload files based on catalog responses.
	OpenFile(filename string) (io.ReadCloser, error)
	// GetTemplatePath parses the specified input template path and returns a compiled
	// list of finished absolute paths to the templates evaluating any glob patterns
	// or folders provided as in.
	GetTemplatePath(target string) ([]string, error)
	// GetTemplatesPath returns a list of absolute paths for the provided template list.
	GetTemplatesPath(definitions []string) ([]string, map[string]error)
	// ResolvePath resolves the path to an absolute one in various ways.
	//
	// It checks if the filename is an absolute path, looks in the current directory
	// or checking the nuclei templates directory. If a second path is given,
	// it also tries to find paths relative to that second path.
	ResolvePath(templateName, second string) (string, error)
}
