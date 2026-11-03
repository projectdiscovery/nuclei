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
	// the exclusions of tagFilter other than severities, see filters
	exclusions *templates.TagFilter
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
	// IncludeTags is not an inclusion filter: it lifts the exclusion of the
	// same tags
	exclusions, err := templates.NewTagFilter(&templates.TagFilterConfig{
		ExcludeTags:      options.Options.ExcludeTags,
		IncludeTags:      options.Options.IncludeTags,
		ExcludeIds:       options.Options.ExcludeIds,
		ExcludeProtocols: options.Options.ExcludeProtocols,
	})
	if err != nil {
		return nil, err
	}
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: options.Options.IncludeTemplates,
		ExcludedTemplates: options.Options.ExcludedTemplates,
	}, options.Catalog)

	loader := &workflowLoader{
		pathFilter: pathFilter,
		tagFilter:  tagFilter,
		exclusions: exclusions,
		options:    options,
		parsed:     make(map[string]*templates.Template),
	}
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

func (w *workflowLoader) GetTemplatePathsByTags(templateTags []string, noValidate bool) []string {
	var loadedTemplates []string
	for _, path := range w.templatesDirectoryPaths() {
		// the step's tags select the templates and the filters then decide
		// which of them load, as for the templates of a template step
		template := w.parseTemplate(path)
		if template == nil || !selectedByTags(template, templateTags) {
			continue
		}
		if matched, _ := templates.MatchLoadFilters(template, path, w.filters(noValidate), nil); matched {
			loadedTemplates = append(loadedTemplates, path)
		}
	}
	return loadedTemplates
}

// selectedByTags reports whether a workflow step that selects templates by
// tags selects template, which it does when template has one of tags.
// Workflows are never selected, as a workflow cannot run as a step.
func selectedByTags(template *templates.Template, tags []string) bool {
	if len(template.Workflows) > 0 {
		return false
	}
	return slices.ContainsFunc(template.Info.Tags.ToSlice(), func(tag string) bool {
		return slices.Contains(tags, tag)
	})
}

func (w *workflowLoader) GetTemplatePaths(templatesList []string, noValidate bool) []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath(templatesList)
	for template, err := range errs {
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}
	templatesPathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatesPathMap))
	for templatePath := range templatesPathMap {
		matched, err := w.options.Parser.LoadTemplate(templatePath, w.filters(noValidate), nil, w.options.Catalog)
		if err != nil && !matched {
			gologger.Warning().Msg(err.Error())
		} else if matched {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}

// filters returns the filters that decide which templates a workflow step
// loads. With noValidate, set for a step whose subtemplates loaded, only the
// exclusions apply: the step must load for its subtemplates to run, but an
// excluded template never runs. Excluded severities do not apply either: a
// step with subtemplates does not report its own results, so excluding its
// severity would only keep its subtemplates from running. A late
// out-of-band (interactsh) match of the step is the exception: it is
// reported whatever its severity, as with -s.
func (w *workflowLoader) filters(noValidate bool) *templates.TagFilter {
	if noValidate {
		return w.exclusions
	}
	return w.tagFilter
}
