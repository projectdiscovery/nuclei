package loader

import (
	"errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
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

	Tags              []string
	ExcludeTags       []string
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string

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
			Tags:              config.Tags,
			ExcludeTags:       config.ExcludeTags,
			Authors:           config.Authors,
			Severities:        config.Severities,
			ExcludeSeverities: config.ExcludeSeverities,
			IncludeTags:       config.IncludeTags,
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
func (store *Store) ValidateTemplates(templatesList, workflowsList []string) error {
	templatePaths := store.config.Catalog.GetTemplatesPath(templatesList)
	workflowPaths := store.config.Catalog.GetTemplatesPath(workflowsList)

	filteredTemplatePaths := store.pathFilter.Match(templatePaths)
	filteredWorkflowPaths := store.pathFilter.Match(workflowPaths)

	if areTemplatesValid(store, filteredTemplatePaths) && areWorkflowsValid(store, filteredWorkflowPaths) {
		return nil
	}
	return errors.New("an error occurred during templates validation")
}

func areWorkflowsValid(store *Store, filteredWorkflowPaths map[string]struct{}) bool {
	return areWorkflowOrTemplatesValid(store, filteredWorkflowPaths, true, func(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
		return parsers.LoadWorkflow(templatePath)
	})
}

func areTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}) bool {
	return areWorkflowOrTemplatesValid(store, filteredTemplatePaths, false, func(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
		return parsers.LoadTemplate(templatePath, store.tagFilter, nil)
	})
}

func areWorkflowOrTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}, isWorkflow bool, load func(templatePath string, tagFilter *filter.TagFilter) (bool, error)) bool {
	areTemplatesValid := true
	for templatePath := range filteredTemplatePaths {
		if _, err := load(templatePath, store.tagFilter); err != nil {
			if isParsingError("Error occurred loading template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
				continue
			}
		}

		template, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			if isParsingError("Error occurred parsing template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
			}
		} else {
			if !isWorkflow && len(template.Workflows) > 0 {
				return true
			}
		}
	}
	return areTemplatesValid
}

func isParsingError(message string, template string, err error) bool {
	if err == templates.ErrCreateTemplateExecutor {
		return false
	}
	if err == filter.ErrExcluded {
		return false
	}
	gologger.Error().Msgf(message, template, err)
	return true
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
		loaded, err := parsers.LoadWorkflow(workflowPath)
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
