package model

// WorkflowLoader is a loader interface required for workflow initialization.
type WorkflowLoader interface {
	// ListTags lists a list of templates for tags from the provided templates directory
	ListTags(workflowTags []string) []string

	// ListTemplates takes a list of templates and returns paths for them
	ListTemplates(templatesList []string, noValidate bool) []string
}
