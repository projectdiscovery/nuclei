package loader

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v3/pkg/keys"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	httpPrefix  = "http://"
	httpsPrefix = "https://"
	AuthStoreId = "auth_store"
)

var (
	TrustedTemplateDomains = []string{"cloud.projectdiscovery.io"}
)

// Config contains the configuration options for the loader
type Config struct {
	StoreId                  string // used to set store id (optional)
	Templates                []string
	TemplateURLs             []string
	Workflows                []string
	WorkflowURLs             []string
	ExcludeTemplates         []string
	IncludeTemplates         []string
	RemoteTemplateDomainList []string
	AITemplatePrompt         string

	Tags              []string
	ExcludeTags       []string
	Protocols         templateTypes.ProtocolTypes
	ExcludeProtocols  templateTypes.ProtocolTypes
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string
	IncludeIds        []string
	ExcludeIds        []string
	IncludeConditions []string

	Catalog         catalog.Catalog
	ExecutorOptions protocols.ExecutorOptions
}

// Store is a storage for loaded nuclei templates
type Store struct {
	id             string // id of the store (optional)
	tagFilter      *templates.TagFilter
	pathFilter     *filter.PathFilter
	config         *Config
	finalTemplates []string
	finalWorkflows []string

	templates []*templates.Template
	workflows []*templates.Template

	preprocessor templates.Preprocessor

	// NotFoundCallback is called for each not found template
	// This overrides error handling for not found templates
	NotFoundCallback func(template string) bool
}

// NewConfig returns a new loader config
func NewConfig(options *types.Options, catalog catalog.Catalog, executerOpts protocols.ExecutorOptions) *Config {
	loaderConfig := Config{
		Templates:                options.Templates,
		Workflows:                options.Workflows,
		RemoteTemplateDomainList: options.RemoteTemplateDomainList,
		TemplateURLs:             options.TemplateURLs,
		WorkflowURLs:             options.WorkflowURLs,
		ExcludeTemplates:         options.ExcludedTemplates,
		Tags:                     options.Tags,
		ExcludeTags:              options.ExcludeTags,
		IncludeTemplates:         options.IncludeTemplates,
		Authors:                  options.Authors,
		Severities:               options.Severities,
		ExcludeSeverities:        options.ExcludeSeverities,
		IncludeTags:              options.IncludeTags,
		IncludeIds:               options.IncludeIds,
		ExcludeIds:               options.ExcludeIds,
		Protocols:                options.Protocols,
		ExcludeProtocols:         options.ExcludeProtocols,
		IncludeConditions:        options.IncludeConditions,
		Catalog:                  catalog,
		ExecutorOptions:          executerOpts,
		AITemplatePrompt:         options.AITemplatePrompt,
	}
	loaderConfig.RemoteTemplateDomainList = append(loaderConfig.RemoteTemplateDomainList, TrustedTemplateDomains...)
	return &loaderConfig
}

// New creates a new template store based on provided configuration
func New(cfg *Config) (*Store, error) {
	tagFilter, err := templates.NewTagFilter(&templates.TagFilterConfig{
		Tags:              cfg.Tags,
		ExcludeTags:       cfg.ExcludeTags,
		Authors:           cfg.Authors,
		Severities:        cfg.Severities,
		ExcludeSeverities: cfg.ExcludeSeverities,
		IncludeTags:       cfg.IncludeTags,
		IncludeIds:        cfg.IncludeIds,
		ExcludeIds:        cfg.ExcludeIds,
		Protocols:         cfg.Protocols,
		ExcludeProtocols:  cfg.ExcludeProtocols,
		IncludeConditions: cfg.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}

	store := &Store{
		id:        cfg.StoreId,
		config:    cfg,
		tagFilter: tagFilter,
		pathFilter: filter.NewPathFilter(&filter.PathFilterConfig{
			IncludedTemplates: cfg.IncludeTemplates,
			ExcludedTemplates: cfg.ExcludeTemplates,
		}, cfg.Catalog),
		finalTemplates: cfg.Templates,
		finalWorkflows: cfg.Workflows,
	}

	// Do a check to see if we have URLs in templates flag, if so
	// we need to processs them separately and remove them from the initial list
	var templatesFinal []string
	for _, template := range cfg.Templates {
		// TODO: Add and replace this with urlutil.IsURL() helper
		if stringsutil.HasPrefixAny(template, httpPrefix, httpsPrefix) {
			cfg.TemplateURLs = append(cfg.TemplateURLs, template)
		} else {
			templatesFinal = append(templatesFinal, template)
		}
	}

	// fix editor paths
	remoteTemplates := []string{}
	for _, v := range cfg.TemplateURLs {
		if _, err := urlutil.Parse(v); err == nil {
			remoteTemplates = append(remoteTemplates, handleTemplatesEditorURLs(v))
		} else {
			templatesFinal = append(templatesFinal, v) // something went wrong, treat it as a file
		}
	}
	cfg.TemplateURLs = remoteTemplates
	store.finalTemplates = templatesFinal

	urlBasedTemplatesProvided := len(cfg.TemplateURLs) > 0 || len(cfg.WorkflowURLs) > 0
	if urlBasedTemplatesProvided {
		remoteTemplates, remoteWorkflows, err := getRemoteTemplatesAndWorkflows(cfg.TemplateURLs, cfg.WorkflowURLs, cfg.RemoteTemplateDomainList)
		if err != nil {
			return store, err
		}
		store.finalTemplates = append(store.finalTemplates, remoteTemplates...)
		store.finalWorkflows = append(store.finalWorkflows, remoteWorkflows...)
	}

	// Handle AI template generation if prompt is provided
	if len(cfg.AITemplatePrompt) > 0 {
		aiTemplates, err := getAIGeneratedTemplates(cfg.AITemplatePrompt, cfg.ExecutorOptions.Options)
		if err != nil {
			return nil, err
		}
		store.finalTemplates = append(store.finalTemplates, aiTemplates...)
	}

	// Handle a dot as the current working directory
	if len(store.finalTemplates) == 1 && store.finalTemplates[0] == "." {
		currentDirectory, err := os.Getwd()
		if err != nil {
			return nil, errors.Wrap(err, "could not get current directory")
		}
		store.finalTemplates = []string{currentDirectory}
	}

	// Handle a case with no templates or workflows, where we use base directory
	if len(store.finalTemplates) == 0 && len(store.finalWorkflows) == 0 && !urlBasedTemplatesProvided {
		store.finalTemplates = []string{config.DefaultConfig.TemplatesDirectory}
	}

	return store, nil
}

func handleTemplatesEditorURLs(input string) string {
	parsed, err := url.Parse(input)
	if err != nil {
		return input
	}
	if !strings.HasSuffix(parsed.Hostname(), "cloud.projectdiscovery.io") {
		return input
	}
	if strings.HasSuffix(parsed.Path, ".yaml") {
		return input
	}
	parsed.Path = fmt.Sprintf("%s.yaml", parsed.Path)
	finalURL := parsed.String()
	return finalURL
}

// ReadTemplateFromURI should only be used for viewing templates
// and should not be used anywhere else like loading and executing templates
// there is no sandbox restriction here
func (store *Store) ReadTemplateFromURI(uri string, remote bool) ([]byte, error) {
	if stringsutil.HasPrefixAny(uri, httpPrefix, httpsPrefix) && remote {
		uri = handleTemplatesEditorURLs(uri)
		remoteTemplates, _, err := getRemoteTemplatesAndWorkflows([]string{uri}, nil, store.config.RemoteTemplateDomainList)
		if err != nil || len(remoteTemplates) == 0 {
			return nil, errorutil.NewWithErr(err).Msgf("Could not load template %s: got %v", uri, remoteTemplates)
		}
		resp, err := retryablehttp.Get(remoteTemplates[0])
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	} else {
		return os.ReadFile(uri)
	}
}

func (store *Store) ID() string {
	return store.id
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
	store.workflows = store.LoadWorkflows(store.finalWorkflows)
}

var templateIDPathMap map[string]string

func init() {
	templateIDPathMap = make(map[string]string)
}

// LoadTemplatesOnlyMetadata loads only the metadata of the templates
func (store *Store) LoadTemplatesOnlyMetadata() error {
	templatePaths, errs := store.config.Catalog.GetTemplatesPath(store.finalTemplates)
	store.logErroredTemplates(errs)

	filteredTemplatePaths := store.pathFilter.Match(templatePaths)

	validPaths := make(map[string]struct{})
	for templatePath := range filteredTemplatePaths {
		loaded, err := store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
		if loaded || store.pathFilter.MatchIncluded(templatePath) {
			validPaths[templatePath] = struct{}{}
		}
		if err != nil {
			if strings.Contains(err.Error(), templates.ErrExcluded.Error()) {
				stats.Increment(templates.TemplatesExcludedStats)
				if config.DefaultConfig.LogAllEvents {
					gologger.Print().Msgf("[%v] %v\n", aurora.Yellow("WRN").String(), err.Error())
				}
				continue
			}
			gologger.Warning().Msg(err.Error())
		}
	}
	parserItem, ok := store.config.ExecutorOptions.Parser.(*templates.Parser)
	if !ok {
		return errors.New("invalid parser")
	}
	templatesCache := parserItem.Cache()

	for templatePath := range validPaths {
		template, _, _ := templatesCache.Has(templatePath)

		if len(template.RequestsHeadless) > 0 && !store.config.ExecutorOptions.Options.Headless {
			continue
		}

		if len(template.RequestsCode) > 0 && !store.config.ExecutorOptions.Options.EnableCodeTemplates {
			continue
		}

		if template.IsFuzzing() && !store.config.ExecutorOptions.Options.DAST {
			continue
		}

		if template.SelfContained && !store.config.ExecutorOptions.Options.EnableSelfContainedTemplates {
			continue
		}

		if template.HasFileProtocol() && !store.config.ExecutorOptions.Options.EnableFileTemplates {
			continue
		}

		if template != nil {
			template.Path = templatePath
			store.templates = append(store.templates, template)
		}
	}
	return nil
}

// ValidateTemplates takes a list of templates and validates them
// erroring out on discovering any faulty templates.
func (store *Store) ValidateTemplates() error {
	templatePaths, errs := store.config.Catalog.GetTemplatesPath(store.finalTemplates)
	store.logErroredTemplates(errs)
	workflowPaths, errs := store.config.Catalog.GetTemplatesPath(store.finalWorkflows)
	store.logErroredTemplates(errs)

	filteredTemplatePaths := store.pathFilter.Match(templatePaths)
	filteredWorkflowPaths := store.pathFilter.Match(workflowPaths)

	if store.areTemplatesValid(filteredTemplatePaths) && store.areWorkflowsValid(filteredWorkflowPaths) {
		return nil
	}
	return errors.New("errors occurred during template validation")
}

func (store *Store) areWorkflowsValid(filteredWorkflowPaths map[string]struct{}) bool {
	return store.areWorkflowOrTemplatesValid(filteredWorkflowPaths, true, func(templatePath string, tagFilter *templates.TagFilter) (bool, error) {
		return false, nil
		// return store.config.ExecutorOptions.Parser.LoadWorkflow(templatePath, store.config.Catalog)
	})
}

func (store *Store) areTemplatesValid(filteredTemplatePaths map[string]struct{}) bool {
	return store.areWorkflowOrTemplatesValid(filteredTemplatePaths, false, func(templatePath string, tagFilter *templates.TagFilter) (bool, error) {
		return false, nil
		// return store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
	})
}

func (store *Store) areWorkflowOrTemplatesValid(filteredTemplatePaths map[string]struct{}, isWorkflow bool, load func(templatePath string, tagFilter *templates.TagFilter) (bool, error)) bool {
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
				continue
			}
		} else if template == nil {
			// NOTE(dwisiswant0): possibly global matchers template.
			// This could definitely be handled better, for example by returning an
			// `ErrGlobalMatchersTemplate` during `templates.Parse` and checking it
			// with `errors.Is`.
			//
			// However, I'm not sure if every reference to it should be handled
			// that way. Returning a `templates.Template` pointer would mean it's
			// an active template (sending requests), and adding a specific field
			// like `isGlobalMatchers` in `templates.Template` (then checking it
			// with a `*templates.Template.IsGlobalMatchersEnabled` method) would
			// just introduce more unknown issues - like during template
			// clustering, AFAIK.
			continue
		} else {
			if existingTemplatePath, found := templateIDPathMap[template.ID]; !found {
				templateIDPathMap[template.ID] = templatePath
			} else {
				// TODO: until https://github.com/projectdiscovery/nuclei-templates/issues/11324 is deployed
				// disable strict validation to allow GH actions to run
				// areTemplatesValid = false
				gologger.Warning().Msgf("Found duplicate template ID during validation '%s' => '%s': %s\n", templatePath, existingTemplatePath, template.ID)
			}
			if !isWorkflow && len(template.Workflows) > 0 {
				continue
			}
		}
		if isWorkflow {
			if !areWorkflowTemplatesValid(store, template.Workflows) {
				areTemplatesValid = false
				continue
			}
		}
	}
	return areTemplatesValid
}

func areWorkflowTemplatesValid(store *Store, workflows []*workflows.WorkflowTemplate) bool {
	for _, workflow := range workflows {
		if !areWorkflowTemplatesValid(store, workflow.Subtemplates) {
			return false
		}
		_, err := store.config.Catalog.GetTemplatePath(workflow.Template)
		if err != nil {
			if isParsingError("Error occurred loading template %s: %s\n", workflow.Template, err) {
				return false
			}
		}
	}
	return true
}

func isParsingError(message string, template string, err error) bool {
	if errors.Is(err, templates.ErrExcluded) {
		return false
	}
	if errors.Is(err, templates.ErrCreateTemplateExecutor) {
		return false
	}
	gologger.Error().Msgf(message, template, err)
	return true
}

// LoadTemplates takes a list of templates and returns paths for them
func (store *Store) LoadTemplates(templatesList []string) []*templates.Template {
	return store.LoadTemplatesWithTags(templatesList, nil)
}

// LoadWorkflows takes a list of workflows and returns paths for them
func (store *Store) LoadWorkflows(workflowsList []string) []*templates.Template {
	includedWorkflows, errs := store.config.Catalog.GetTemplatesPath(workflowsList)
	store.logErroredTemplates(errs)
	workflowPathMap := store.pathFilter.Match(includedWorkflows)

	loadedWorkflows := make([]*templates.Template, 0, len(workflowPathMap))
	for workflowPath := range workflowPathMap {
		loaded, err := store.config.ExecutorOptions.Parser.LoadWorkflow(workflowPath, store.config.Catalog)
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

// LoadTemplatesWithTags takes a list of templates and extra tags
// returning templates that match.
func (store *Store) LoadTemplatesWithTags(templatesList, tags []string) []*templates.Template {
	includedTemplates, errs := store.config.Catalog.GetTemplatesPath(templatesList)
	store.logErroredTemplates(errs)
	templatePathMap := store.pathFilter.Match(includedTemplates)

	loadedTemplates := sliceutil.NewSyncSlice[*templates.Template]()

	loadTemplate := func(tmpl *templates.Template) {
		loadedTemplates.Append(tmpl)
		// increment signed/unsigned counters
		if tmpl.Verified {
			if tmpl.TemplateVerifier == "" {
				templates.SignatureStats[keys.PDVerifier].Add(1)
			} else {
				templates.SignatureStats[tmpl.TemplateVerifier].Add(1)
			}
		} else {
			templates.SignatureStats[templates.Unsigned].Add(1)
		}
	}

	var wgLoadTemplates sync.WaitGroup

	for templatePath := range templatePathMap {
		wgLoadTemplates.Add(1)
		go func(templatePath string) {
			defer wgLoadTemplates.Done()

			loaded, err := store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, tags, store.config.Catalog)
			if loaded || store.pathFilter.MatchIncluded(templatePath) {
				parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
				if err != nil {
					// exclude templates not compatible with offline matching from total runtime warning stats
					if !errors.Is(err, templates.ErrIncompatibleWithOfflineMatching) {
						stats.Increment(templates.RuntimeWarningsStats)
					}
					gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
				} else if parsed != nil {
					if !parsed.Verified && store.config.ExecutorOptions.Options.DisableUnsignedTemplates {
						// skip unverified templates when prompted to
						stats.Increment(templates.SkippedUnsignedStats)
						return
					}

					if parsed.SelfContained && !store.config.ExecutorOptions.Options.EnableSelfContainedTemplates {
						stats.Increment(templates.ExcludedSelfContainedStats)
						return
					}

					if parsed.HasFileProtocol() && !store.config.ExecutorOptions.Options.EnableFileTemplates {
						stats.Increment(templates.ExcludedFileStats)
						return
					}

					// if template has request signature like aws then only signed and verified templates are allowed
					if parsed.UsesRequestSignature() && !parsed.Verified {
						stats.Increment(templates.SkippedRequestSignatureStats)
						return
					}
					// DAST only templates
					// Skip DAST filter when loading auth templates
					if store.ID() != AuthStoreId && store.config.ExecutorOptions.Options.DAST {
						// check if the template is a DAST template
						// also allow global matchers template to be loaded
						if parsed.IsFuzzing() || parsed.Options.GlobalMatchers != nil && parsed.Options.GlobalMatchers.HasMatchers() {
							loadTemplate(parsed)
						}
					} else if len(parsed.RequestsHeadless) > 0 && !store.config.ExecutorOptions.Options.Headless {
						// donot include headless template in final list if headless flag is not set
						stats.Increment(templates.ExcludedHeadlessTmplStats)
						if config.DefaultConfig.LogAllEvents {
							gologger.Print().Msgf("[%v] Headless flag is required for headless template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if len(parsed.RequestsCode) > 0 && !store.config.ExecutorOptions.Options.EnableCodeTemplates {
						// donot include 'Code' protocol custom template in final list if code flag is not set
						stats.Increment(templates.ExcludedCodeTmplStats)
						if config.DefaultConfig.LogAllEvents {
							gologger.Print().Msgf("[%v] Code flag is required for code protocol template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if len(parsed.RequestsCode) > 0 && !parsed.Verified && len(parsed.Workflows) == 0 {
						// donot include unverified 'Code' protocol custom template in final list
						stats.Increment(templates.SkippedCodeTmplTamperedStats)
						// these will be skipped so increment skip counter
						stats.Increment(templates.SkippedUnsignedStats)
						if config.DefaultConfig.LogAllEvents {
							gologger.Print().Msgf("[%v] Tampered/Unsigned template at %v.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if parsed.IsFuzzing() && !store.config.ExecutorOptions.Options.DAST {
						stats.Increment(templates.ExludedDastTmplStats)
						if config.DefaultConfig.LogAllEvents {
							gologger.Print().Msgf("[%v] -dast flag is required for DAST template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else {
						loadTemplate(parsed)
					}
				}
			}
			if err != nil {
				if strings.Contains(err.Error(), templates.ErrExcluded.Error()) {
					stats.Increment(templates.TemplatesExcludedStats)
					if config.DefaultConfig.LogAllEvents {
						gologger.Print().Msgf("[%v] %v\n", aurora.Yellow("WRN").String(), err.Error())
					}
					return
				}
				gologger.Warning().Msg(err.Error())
			}
		}(templatePath)
	}

	wgLoadTemplates.Wait()

	sort.SliceStable(loadedTemplates.Slice, func(i, j int) bool {
		return loadedTemplates.Slice[i].Path < loadedTemplates.Slice[j].Path
	})

	return loadedTemplates.Slice
}

// IsHTTPBasedProtocolUsed returns true if http/headless protocol is being used for
// any templates.
func IsHTTPBasedProtocolUsed(store *Store) bool {
	templates := append(store.Templates(), store.Workflows()...)

	for _, template := range templates {
		if len(template.RequestsHTTP) > 0 || len(template.RequestsHeadless) > 0 {
			return true
		}
		if len(template.Workflows) > 0 {
			if workflowContainsProtocol(template.Workflows) {
				return true
			}
		}
	}
	return false
}

func workflowContainsProtocol(workflow []*workflows.WorkflowTemplate) bool {
	for _, workflow := range workflow {
		for _, template := range workflow.Matchers {
			if workflowContainsProtocol(template.Subtemplates) {
				return true
			}
		}
		for _, template := range workflow.Subtemplates {
			if workflowContainsProtocol(template.Subtemplates) {
				return true
			}
		}
		for _, executer := range workflow.Executers {
			if executer.TemplateType == templateTypes.HTTPProtocol || executer.TemplateType == templateTypes.HeadlessProtocol {
				return true
			}
		}
	}
	return false
}

func (s *Store) logErroredTemplates(erred map[string]error) {
	for template, err := range erred {
		if s.NotFoundCallback == nil || !s.NotFoundCallback(template) {
			gologger.Error().Msgf("Could not find template '%s': %s", template, err)
		}
	}
}
