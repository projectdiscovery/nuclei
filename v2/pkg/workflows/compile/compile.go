package compile

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/load"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// WorkflowLoader is a loader interface required for workflow
// initialization.
type WorkflowLoader interface {
	// ListTags lists a list of templates for tags from the provided templates directory
	ListTags(tags []string) []string
	// ListTemplates takes a list of templates and returns paths for them
	ListTemplates(templatesList []string, noValidate bool) []string
}

type workflowLoader struct {
	pathFilter *filter.PathFilter
	tagFilter  *filter.TagFilter
	options    *protocols.ExecuterOptions
}

// NewLoader returns a new workflow loader structure
func NewLoader(options *protocols.ExecuterOptions) (WorkflowLoader, error) {
	tagFilter := filter.New(&filter.Config{
		Tags:        options.Options.Tags,
		ExcludeTags: options.Options.ExcludeTags,
		Authors:     options.Options.Author,
		Severities:  options.Options.Severity,
		IncludeTags: options.Options.IncludeTags,
	})
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: options.Options.IncludeTemplates,
		ExcludedTemplates: options.Options.ExcludedTemplates,
	}, options.Catalog)
	return &workflowLoader{pathFilter: pathFilter, tagFilter: tagFilter, options: options}, nil
}

// ListTags lists a list of templates for tags from the provided templates directory
func (w *workflowLoader) ListTags(tags []string) []string {
	includedTemplates := w.options.Catalog.GetTemplatesPath([]string{w.options.Options.TemplatesDirectory})
	templatesMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesMap))
	for k := range templatesMap {
		loaded, err := load.Load(k, false, tags, w.tagFilter)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", k, err)
		} else if loaded {
			loadedTemplates = append(loadedTemplates, k)
		}
	}
	return loadedTemplates
}

// ListTemplates takes a list of templates and returns paths for them
func (w *workflowLoader) ListTemplates(templatesList []string, noValidate bool) []string {
	includedTemplates := w.options.Catalog.GetTemplatesPath(templatesList)
	templatesMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesMap))
	for k := range templatesMap {
		matched, err := load.Load(k, false, nil, w.tagFilter)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", k, err)
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, k)
		}
	}
	return loadedTemplates
}
