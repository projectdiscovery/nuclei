package workflows

// Workflow is a workflow structure parsed from a yaml file
type Workflow struct {
	// Logic contains the workflow logic to execute
	Logic string `yaml:"logic"`
	// Variables contains the variables accessible to the pseudo-code
	Variables map[string]string `yaml:"variables"`
}
