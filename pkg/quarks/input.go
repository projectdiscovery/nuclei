package quarks

// Input is the input read from the template file defining all components
// of the template file and also specify whether loaded input is a
// workflow or a template.
type Input struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info Info `yaml:"info"`
}

// Info contains information about the request template
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
