package workflows

// Workflow is a workflow to execute with chained requests, etc.
type Workflow struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info map[string]string `yaml:"info"`
	// CookieReuse makes all cookies shared by templates within the workflow
	CookieReuse bool `yaml:"cookie-reuse,omitempty"`
	// Variables contains the variables accessible to the pseudo-code
	Variables map[string]string `yaml:"variables"`
	// Logic contains the workflow pseudo-code
	Logic string `yaml:"logic"`
	path  string
}

// GetPath of the workflow
func (w *Workflow) GetPath() string {
	return w.path
}
