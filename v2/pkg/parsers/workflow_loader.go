package parsers

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

type workflowLoader struct {
	pathFilter *filter.PathFilter
	tagFilter  *filter.TagFilter
	options    *protocols.ExecutorOptions
}

// NewLoader returns a new workflow loader structure
func NewLoader(options *protocols.ExecutorOptions) (model.WorkflowLoader, error) {
	tagFilter, err := filter.New(&filter.Config{
		Authors:           options.Options.Authors,
		Tags:              options.Options.Tags,
		ExcludeTags:       options.Options.ExcludeTags,
		IncludeTags:       options.Options.IncludeTags,
		IncludeIds:        options.Options.IncludeIds,
		ExcludeIds:        options.Options.ExcludeIds,
		Severities:        options.Options.Severities,
		ExcludeSeverities: options.Options.ExcludeSeverities,
		Protocols:         options.Options.Protocols,
		ExcludeProtocols:  options.Options.ExcludeProtocols,
		IncludeConditions: options.Options.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: options.Options.IncludeTemplates,
		ExcludedTemplates: options.Options.ExcludedTemplates,
	}, options.Catalog)

	return &workflowLoader{pathFilter: pathFilter, tagFilter: tagFilter, options: options}, nil
}

func (w *workflowLoader) GetTemplatePathsByTags(templateTags []string) []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath([]string{config.DefaultConfig.TemplatesDirectory})
	for template, err := range errs {
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}

	templatePathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, _ := LoadTemplate(templatePath, w.tagFilter, templateTags, w.options.Catalog)
		if loaded {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}

func (w *workflowLoader) GetTemplatePaths(templatesList []string, noValidate bool) []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath(templatesList)
	for template, err := range errs {
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}
	templatesPathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesPathMap))
	for templatePath := range templatesPathMap {
		matched, err := LoadTemplate(templatePath, w.tagFilter, nil, w.options.Catalog)
		if err != nil && !matched {
			gologger.Warning().Msg(err.Error())
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}
