package parsers

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

type workflowLoader struct {
	pathFilter *filter.PathFilter
	tagFilter  *filter.TagFilter
	options    *protocols.ExecuterOptions
}

// NewLoader returns a new workflow loader structure
func NewLoader(options *protocols.ExecuterOptions) (model.WorkflowLoader, error) {
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
func (w *workflowLoader) ListTags(workflowTags []string) []string {
	includedTemplates := w.options.Catalog.GetTemplatesPath([]string{w.options.Options.TemplatesDirectory})
	templatesMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesMap))
	for k := range templatesMap {
		loaded, err := Load(k, false, workflowTags, w.tagFilter)
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
		matched, err := Load(k, false, nil, w.tagFilter)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", k, err)
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, k)
		}
	}
	return loadedTemplates
}
