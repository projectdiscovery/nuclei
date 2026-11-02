package model

// TODO shouldn't this rather be TemplateLoader?

// WorkflowLoader is a loader interface required for workflow initialization.
type WorkflowLoader interface {
	// GetTemplatePathsByTags returns the paths of the templates in the
	// templates directory that have one of tags. noValidate is as in
	// GetTemplatePaths.
	GetTemplatePathsByTags(tags []string, noValidate bool) []string

	// GetTemplatePaths takes a list of templates and returns paths for them.
	// With noValidate, only the exclusion filters apply, except excluded
	// severities: excluded tags, IDs, protocols and paths.
	GetTemplatePaths(templatesList []string, noValidate bool) []string
}
