package loader

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/load"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// Config contains the configuration options for the loader
type Config struct {
	Templates        []string
	Workflows        []string
	ExcludeTemplates []string
	IncludeTemplates []string

	Tags        []string
	ExcludeTags []string
	Authors     []string
	Severities  []string
	IncludeTags []string

	Catalog            *catalog.Catalog
	ExecutorOptions    protocols.ExecuterOptions
	TemplatesDirectory string
}

// Store is a storage for loaded nuclei templates
type Store struct {
	tagFilter      *filter.TagFilter
	pathFilter     *filter.PathFilter
	config         *Config
	finalTemplates []string

	templates []*templates.Template
	workflows []*templates.Template

	preprocessor templates.Preprocessor
}

// New creates a new template store based on provided configuration
func New(config *Config) (*Store, error) {
	// Create a tag filter based on provided configuration
	store := &Store{
		config: config,
		tagFilter: filter.New(&filter.Config{
			Tags:        config.Tags,
			ExcludeTags: config.ExcludeTags,
			Authors:     config.Authors,
			Severities:  config.Severities,
			IncludeTags: config.IncludeTags,
		}),
		pathFilter: filter.NewPathFilter(&filter.PathFilterConfig{
			IncludedTemplates: config.IncludeTemplates,
			ExcludedTemplates: config.ExcludeTemplates,
		}, config.Catalog),
	}

	// Handle a case with no templates or workflows, where we use base directory
	if len(config.Templates) == 0 && len(config.Workflows) == 0 {
		config.Templates = append(config.Templates, config.TemplatesDirectory)
	}
	store.finalTemplates = append(store.finalTemplates, config.Templates...)
	return store, nil
}

// Templates returns all the templates in the store
func (s *Store) Templates() []*templates.Template {
	return s.templates
}

// Workflows returns all the workflows in the store
func (s *Store) Workflows() []*templates.Template {
	return s.workflows
}

// RegisterPreprocessor allows a custom preprocessor to be passed to the store to run against templates
func (s *Store) RegisterPreprocessor(preprocessor templates.Preprocessor) {
	s.preprocessor = preprocessor
}

// Load loads all the templates from a store, performs filtering and returns
// the complete compiled templates for a nuclei execution configuration.
func (s *Store) Load() {
	s.templates = s.LoadTemplates(s.finalTemplates)
	s.workflows = s.LoadWorkflows(s.config.Workflows)
}

// ValidateTemplates takes a list of templates and validates them
// erroring out on discovering any faulty templates.
func (s *Store) ValidateTemplates(templatesList, workflowsList []string) bool {
	includedTemplates := s.config.Catalog.GetTemplatesPath(templatesList)
	includedWorkflows := s.config.Catalog.GetTemplatesPath(workflowsList)
	templatesMap := s.pathFilter.Match(includedTemplates)
	workflowsMap := s.pathFilter.Match(includedWorkflows)

	notErrored := true
	for k := range templatesMap {
		_, err := s.loadTemplate(k, false)
		if err != nil {
			if strings.Contains(err.Error(), "cannot create template executer") {
				continue
			}
			if err == filter.ErrExcluded {
				continue
			}
			notErrored = false
			gologger.Error().Msgf("Error occurred loading template %s: %s\n", k, err)
			continue
		}
		_, err = templates.Parse(k, s.preprocessor, s.config.ExecutorOptions)
		if err != nil {
			if strings.Contains(err.Error(), "cannot create template executer") {
				continue
			}
			if err == filter.ErrExcluded {
				continue
			}
			notErrored = false
			gologger.Error().Msgf("Error occurred parsing template %s: %s\n", k, err)
		}
	}
	for k := range workflowsMap {
		_, err := s.loadTemplate(k, true)
		if err != nil {
			if strings.Contains(err.Error(), "cannot create template executer") {
				continue
			}
			if err == filter.ErrExcluded {
				continue
			}
			notErrored = false
			gologger.Error().Msgf("Error occurred loading workflow %s: %s\n", k, err)
		}
		_, err = templates.Parse(k, s.preprocessor, s.config.ExecutorOptions)
		if err != nil {
			if strings.Contains(err.Error(), "cannot create template executer") {
				continue
			}
			if err == filter.ErrExcluded {
				continue
			}
			notErrored = false
			gologger.Error().Msgf("Error occurred parsing workflow %s: %s\n", k, err)
		}
	}
	return notErrored
}

// LoadTemplates takes a list of templates and returns paths for them
func (s *Store) LoadTemplates(templatesList []string) []*templates.Template {
	includedTemplates := s.config.Catalog.GetTemplatesPath(templatesList)
	templatesMap := s.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]*templates.Template, 0, len(templatesMap))
	for k := range templatesMap {
		loaded, err := s.loadTemplate(k, false)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", k, err)
		}
		if loaded {
			parsed, err := templates.Parse(k, s.preprocessor, s.config.ExecutorOptions)
			if err != nil {
				gologger.Warning().Msgf("Could not parse template %s: %s\n", k, err)
			} else if parsed != nil {
				loadedTemplates = append(loadedTemplates, parsed)
			}
		}
	}
	return loadedTemplates
}

// LoadWorkflows takes a list of workflows and returns paths for them
func (s *Store) LoadWorkflows(workflowsList []string) []*templates.Template {
	includedWorkflows := s.config.Catalog.GetTemplatesPath(s.config.Workflows)
	workflowsMap := s.pathFilter.Match(includedWorkflows)

	loadedWorkflows := make([]*templates.Template, 0, len(workflowsMap))
	for k := range workflowsMap {
		loaded, err := s.loadTemplate(k, true)
		if err != nil {
			gologger.Warning().Msgf("Could not load workflow %s: %s\n", k, err)
		}
		if loaded {
			parsed, err := templates.Parse(k, s.preprocessor, s.config.ExecutorOptions)
			if err != nil {
				gologger.Warning().Msgf("Could not parse workflow %s: %s\n", k, err)
			} else if parsed != nil {
				loadedWorkflows = append(loadedWorkflows, parsed)
			}
		}
	}
	return loadedWorkflows
}

func (s *Store) loadTemplate(templatePath string, workflow bool) (bool, error) {
	return load.Load(templatePath, workflow, nil, s.tagFilter)
}
