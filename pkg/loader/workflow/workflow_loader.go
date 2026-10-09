package workflow

import (
	"maps"
	"slices"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

type workflowLoader struct {
	pathFilter *filter.PathFilter
	tagFilter  *templates.TagFilter
	options    *protocols.ExecutorOptions

	// every workflow step that selects templates by tag searches the whole
	// templates directory, so it is walked once per loader, and each template
	// is parsed once: going through the parser per step re-stats every cached
	// template, which is millions of stats when loading all workflows
	templatesDirectoryPaths func() []string
	parsedMu                sync.Mutex
	parsed                  map[string]*templates.Template
}

// NewLoader returns a new workflow loader structure
func NewLoader(options *protocols.ExecutorOptions) (model.WorkflowLoader, error) {
	tagFilter, err := templates.NewTagFilter(&templates.TagFilterConfig{
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

	loader := &workflowLoader{pathFilter: pathFilter, tagFilter: tagFilter, options: options, parsed: make(map[string]*templates.Template)}
	loader.templatesDirectoryPaths = sync.OnceValue(loader.listTemplatesDirectory)
	return loader, nil
}

func (w *workflowLoader) listTemplatesDirectory() []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath([]string{config.DefaultConfig.TemplatesDirectory})
	for template, err := range errs {
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}
	return slices.Collect(maps.Keys(w.pathFilter.Match(includedTemplates)))
}

// parseTemplate returns the template at path, or nil if it does not parse.
// The parser is called outside the lock: parsing a workflow compiles it, which
// looks templates up by tag again on the same goroutine.
func (w *workflowLoader) parseTemplate(path string) *templates.Template {
	w.parsedMu.Lock()
	template, ok := w.parsed[path]
	w.parsedMu.Unlock()
	if ok {
		return template
	}

	value, err := w.options.Parser.ParseTemplate(path, w.options.Catalog)
	template, _ = value.(*templates.Template)
	if err != nil {
		template = nil
	}
	w.parsedMu.Lock()
	w.parsed[path] = template
	w.parsedMu.Unlock()
	return template
}

func (w *workflowLoader) GetTemplatePathsByTags(templateTags []string) []string {
	var loadedTemplates []string
	for _, path := range w.templatesDirectoryPaths() {
		template := w.parseTemplate(path)
		if template == nil {
			continue
		}
		if loaded, _ := templates.MatchLoadFilters(template, path, w.tagFilter, templateTags); loaded {
			loadedTemplates = append(loadedTemplates, path)
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
		matched, err := w.options.Parser.LoadTemplate(templatePath, w.tagFilter, nil, w.options.Catalog)
		if err != nil && !matched {
			gologger.Warning().Msg(err.Error())
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}
