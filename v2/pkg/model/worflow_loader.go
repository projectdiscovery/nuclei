package model

// TODO shouldn't this rather be TemplateLoader?

// WorkflowLoader is a loader interface required for workflow initialization.
type WorkflowLoader interface {
	// GetTemplatePathsByTags returns a list of template paths based on the provided tags from the templates directory
	GetTemplatePathsByTags(tags []string) []string

	// GetTemplatePaths takes a list of templates and returns paths for them
	GetTemplatePaths(templatesList []string, noValidate bool) []string
}
