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
		Authors:     options.Options.Authors,
		Severities:  options.Options.Severities,
		IncludeTags: options.Options.IncludeTags,
		IncludeIds:  options.Options.IncludeIds,
		ExcludeIds:  options.Options.ExcludeIds,
	})
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: options.Options.IncludeTemplates,
		ExcludedTemplates: options.Options.ExcludedTemplates,
	}, options.Catalog)
	return &workflowLoader{pathFilter: pathFilter, tagFilter: tagFilter, options: options}, nil
}

func (w *workflowLoader) GetTemplatePathsByTags(templateTags []string) []string {
	includedTemplates := w.options.Catalog.GetTemplatesPath([]string{w.options.Options.TemplatesDirectory})
	templatePathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := LoadTemplate(templatePath, w.tagFilter, templateTags)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		} else if loaded {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}

func (w *workflowLoader) GetTemplatePaths(templatesList []string, noValidate bool) []string {
	includedTemplates := w.options.Catalog.GetTemplatesPath(templatesList)
	templatesPathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesPathMap))
	for templatePath := range templatesPathMap {
		matched, err := LoadTemplate(templatePath, w.tagFilter, nil)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}
