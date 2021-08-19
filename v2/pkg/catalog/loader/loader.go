package loader

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
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
	Severities  severity.Severities
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
func (store *Store) Templates() []*templates.Template {
	return store.templates
}

// Workflows returns all the workflows in the store
func (store *Store) Workflows() []*templates.Template {
	return store.workflows
}

// RegisterPreprocessor allows a custom preprocessor to be passed to the store to run against templates
func (store *Store) RegisterPreprocessor(preprocessor templates.Preprocessor) {
	store.preprocessor = preprocessor
}

// Load loads all the templates from a store, performs filtering and returns
// the complete compiled templates for a nuclei execution configuration.
func (store *Store) Load() {
	store.templates = store.LoadTemplates(store.finalTemplates)
	store.workflows = store.LoadWorkflows(store.config.Workflows)
}

// ValidateTemplates takes a list of templates and validates them
// erroring out on discovering any faulty templates.
func (store *Store) ValidateTemplates(templatesList, workflowsList []string) bool {
	templatePaths := store.config.Catalog.GetTemplatesPath(templatesList)
	workflowPaths := store.config.Catalog.GetTemplatesPath(workflowsList)

	filteredTemplatePaths := store.pathFilter.Match(templatePaths)
	filteredWorkflowPaths := store.pathFilter.Match(workflowPaths)

	notErrored := true
	errorValidationFunc := func(message string, template string, err error) {
		if strings.Contains(err.Error(), "cannot create template executer") {
			return
		}
		if err == filter.ErrExcluded {
			return
		}
		notErrored = false
		gologger.Error().Msgf(message, template, err)
	}
	for templatePath := range filteredTemplatePaths {
		_, err := parsers.LoadTemplate(templatePath, store.tagFilter, nil)
		if err != nil {
			errorValidationFunc("Error occurred loading template %s: %s\n", templatePath, err)
			continue
		}
		_, err = templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			errorValidationFunc("Error occurred parsing template %s: %s\n", templatePath, err)
			continue
		}
	}
	for workflowPath := range filteredWorkflowPaths {
		_, err := parsers.LoadWorkflow(workflowPath, store.tagFilter)
		if err != nil {
			errorValidationFunc("Error occurred loading workflow %s: %s\n", workflowPath, err)
			continue
		}
		_, err = templates.Parse(workflowPath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			errorValidationFunc("Error occurred parsing workflow %s: %s\n", workflowPath, err)
			continue
		}
	}
	return notErrored
}

// LoadTemplates takes a list of templates and returns paths for them
func (store *Store) LoadTemplates(templatesList []string) []*templates.Template {
	includedTemplates := store.config.Catalog.GetTemplatesPath(templatesList)
	templatePathMap := store.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parsers.LoadTemplate(templatePath, store.tagFilter, nil)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		}
		if loaded {
			parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
			} else if parsed != nil {
				loadedTemplates = append(loadedTemplates, parsed)
			}
		}
	}
	return loadedTemplates
}

// LoadWorkflows takes a list of workflows and returns paths for them
func (store *Store) LoadWorkflows(workflowsList []string) []*templates.Template {
	includedWorkflows := store.config.Catalog.GetTemplatesPath(workflowsList)
	workflowPathMap := store.pathFilter.Match(includedWorkflows)

	loadedWorkflows := make([]*templates.Template, 0, len(workflowPathMap))
	for workflowPath := range workflowPathMap {
		loaded, err := parsers.LoadWorkflow(workflowPath, store.tagFilter)
		if err != nil {
			gologger.Warning().Msgf("Could not load workflow %s: %s\n", workflowPath, err)
		}
		if loaded {
			parsed, err := templates.Parse(workflowPath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				gologger.Warning().Msgf("Could not parse workflow %s: %s\n", workflowPath, err)
			} else if parsed != nil {
				loadedWorkflows = append(loadedWorkflows, parsed)
			}
		}
	}
	return loadedWorkflows
}
