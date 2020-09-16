package quarks

// Info contains information about either a template / workflow.
type Info struct {
	// Name is the name of the template
	Name string `yaml:"name"`
	// Author is the name of the author of the template
	Author string `yaml:"author"`
	// Severity optionally describes the severity of the template
	Severity string `yaml:"severity,omitempty"`
	// Description optionally describes the template.
	Description string `yaml:"description,omitempty"`
}

// PathResolver is an interface for resolving relative paths in input files.
type PathResolver interface {
	// GetTemplatePath parses the specified input template path and returns a compiled
	// list of finished absolute paths to the templates evaluating any glob patterns
	// or folders provided as in.
	GetTemplatePath(target string) ([]string, error)

	// ResolvePath resolves the path to an absolute one in various ways.
	//
	// It checks if the filename is an absolute path, looks in the current directory
	// or checking the nuclei templates directory. If a second path is given,
	// it also tries to find paths relative to that second path.
	ResolvePath(templateName, second string) (string, error)
}
