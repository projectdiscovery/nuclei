package workflows

// Workflow is a workflow to execute with chained requests, etc.
type Workflow struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info Info `yaml:"info"`
	// Variables contains the variables accessible to the pseudo-code
	Variables map[string]string `yaml:"variables"`
	// Logic contains the workflow pseudo-code
	Logic string `yaml:"logic"`
}

// Info contains information about workflow
type Info struct {
	// Name is the name of the workflow
	Name string `yaml:"name"`
	// Author is the name of the author of the workflow
	Author string `yaml:"author"`
	// Severity optionally describes the severity of the template
	Severity string `yaml:"severity,omitempty"`
}
