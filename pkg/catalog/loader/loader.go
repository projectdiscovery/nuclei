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
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/keys"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/rs/xid"
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
	ExecutorOptions *protocols.ExecutorOptions
	Logger          *gologger.Logger
}

// Store is a storage for loaded nuclei templates
type Store struct {
	id             string // id of the store (optional)
	tagFilter      *templates.TagFilter
	config         *Config
	finalTemplates []string
	finalWorkflows []string

	templates []*templates.Template
	workflows []*templates.Template

	preprocessor templates.Preprocessor

	logger *gologger.Logger

	// parserCacheOnce is used to cache the parser cache result
	parserCacheOnce func() *templates.Cache

	// metadataIndex is the template metadata cache
	metadataIndex *index.Index

	// indexFilter is the cached filter for metadata matching
	indexFilter *index.Filter

	// saveTemplatesIndexOnce is used to ensure we only save the metadata index
	// once
	saveMetadataIndexOnce func()

	// NotFoundCallback is called for each not found template
	// This overrides error handling for not found templates
	NotFoundCallback func(template string) bool
}

// NewConfig returns a new loader config
func NewConfig(options *types.Options, catalog catalog.Catalog, executerOpts *protocols.ExecutorOptions) *Config {
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
		Logger:                   options.Logger,
	}
	loaderConfig.RemoteTemplateDomainList = append(loaderConfig.RemoteTemplateDomainList, TrustedTemplateDomains...)
	return &loaderConfig
}

// New creates a new template store based on provided configuration
func New(cfg *Config) (*Store, error) {
	// tagFilter only for IncludeConditions (advanced filtering).
	// All other filtering (tags, authors, severities, IDs, protocols, paths) is
	// handled by [index.Filter].
	tagFilter, err := templates.NewTagFilter(&templates.TagFilterConfig{
		IncludeConditions: cfg.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}

	store := &Store{
		id:             cfg.StoreId,
		config:         cfg,
		tagFilter:      tagFilter,
		finalTemplates: cfg.Templates,
		finalWorkflows: cfg.Workflows,
		logger:         cfg.Logger,
	}

	store.parserCacheOnce = sync.OnceValue(func() *templates.Cache {
		if cfg.ExecutorOptions == nil || cfg.ExecutorOptions.Parser == nil {
			return nil
		}

		if parser, ok := cfg.ExecutorOptions.Parser.(*templates.Parser); ok {
			return parser.Cache()
		}

		return nil
	})

	// Initialize metadata index and filter (load from disk & cache for reuse)
	store.metadataIndex = store.loadTemplatesIndex()
	store.indexFilter = store.buildIndexFilter()
	if cfg.ExecutorOptions != nil {
		cfg.ExecutorOptions.TemplateVerificationCallback = store.getTemplateVerification
	}
	store.saveMetadataIndexOnce = sync.OnceFunc(func() {
		if store.metadataIndex == nil {
			return
		}

		if err := store.metadataIndex.Save(); err != nil {
			store.logger.Warning().Msgf("Could not save metadata cache: %v", err)
		} else {
			store.logger.Verbose().Msgf("Saved %d templates to metadata cache", store.metadataIndex.Size())
		}
	})

	// Do a check to see if we have URLs in templates flag, if so
	// we need to process them separately and remove them from the initial list
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

func (store *Store) getTemplateVerification(templatePath string) *protocols.TemplateVerification {
	if store.metadataIndex == nil {
		return nil
	}

	metadata, found := store.metadataIndex.Get(templatePath)
	if !found {
		return nil
	}

	return &protocols.TemplateVerification{
		Verified: metadata.Verified,
		Verifier: metadata.TemplateVerifier,
	}
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
			return nil, errkit.Wrapf(err, "Could not load template %s: got %v", uri, remoteTemplates)
		}

		resp, err := retryablehttp.Get(remoteTemplates[0])
		if err != nil {
			return nil, err
		}

		defer func() {
			_ = resp.Body.Close()
		}()

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

// buildIndexFilter creates an [index.Filter] from the store configuration.
// This filter handles all basic filtering (paths, tags, authors, severities,
// IDs, protocols). Advanced IncludeConditions filtering is handled separately
// by tagFilter.
func (store *Store) buildIndexFilter() *index.Filter {
	includeTemplates, _ := store.config.Catalog.GetTemplatesPath(store.config.IncludeTemplates)
	excludeTemplates, _ := store.config.Catalog.GetTemplatesPath(store.config.ExcludeTemplates)

	return &index.Filter{
		Authors:              store.config.Authors,
		Tags:                 store.config.Tags,
		ExcludeTags:          store.config.ExcludeTags,
		IncludeTags:          store.config.IncludeTags,
		IDs:                  store.config.IncludeIds,
		ExcludeIDs:           store.config.ExcludeIds,
		IncludeTemplates:     includeTemplates,
		ExcludeTemplates:     excludeTemplates,
		Severities:           []severity.Severity(store.config.Severities),
		ExcludeSeverities:    []severity.Severity(store.config.ExcludeSeverities),
		ProtocolTypes:        []templateTypes.ProtocolType(store.config.Protocols),
		ExcludeProtocolTypes: []templateTypes.ProtocolType(store.config.ExcludeProtocols),
	}
}

func (store *Store) loadTemplatesIndex() *index.Index {
	var metadataIdx *index.Index

	idx, err := index.NewDefaultIndex()
	if err != nil {
		store.logger.Warning().Msgf("Could not create metadata cache: %v", err)
	} else {
		metadataIdx = idx
		if err := metadataIdx.Load(); err != nil {
			store.logger.Warning().Msgf("Could not load metadata cache: %v", err)
		}
	}

	return metadataIdx
}

// LoadTemplatesOnlyMetadata loads only the metadata of the templates
func (store *Store) LoadTemplatesOnlyMetadata() error {
	defer store.saveMetadataIndexOnce()

	templatePaths, errs := store.config.Catalog.GetTemplatesPath(store.finalTemplates)
	store.logErroredTemplates(errs)

	indexFilter := store.indexFilter
	validPaths := make(map[string]struct{})

	for _, templatePath := range templatePaths {
		if store.metadataIndex != nil {
			if metadata, found := store.metadataIndex.Get(templatePath); found {
				if !indexFilter.Matches(metadata) {
					continue
				}

				if store.tagFilter != nil {
					loaded, err := store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
					if !loaded {
						if err != nil && strings.Contains(err.Error(), templates.ErrExcluded.Error()) {
							stats.Increment(templates.TemplatesExcludedStats)
							if config.DefaultConfig.LogAllEvents {
								store.logger.Print().Msgf("[%v] %v\n", aurora.Yellow("WRN").String(), err.Error())
							}
						}
						continue
					}
				}

				validPaths[templatePath] = struct{}{}
				continue
			}
		}

		loaded, err := store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
		if loaded {
			templatesCache := store.parserCacheOnce()
			if templatesCache != nil {
				if template, _, _ := templatesCache.Has(templatePath); template != nil {
					var metadata *index.Metadata

					if store.metadataIndex != nil {
						metadata, _ = store.metadataIndex.SetFromTemplate(templatePath, template)
					} else {
						metadata = index.NewMetadataFromTemplate(templatePath, template)
					}

					if !indexFilter.Matches(metadata) {
						continue
					}

					validPaths[templatePath] = struct{}{}
					continue
				}
			}

			validPaths[templatePath] = struct{}{}
		}

		if err != nil {
			if strings.Contains(err.Error(), templates.ErrExcluded.Error()) {
				stats.Increment(templates.TemplatesExcludedStats)
				if config.DefaultConfig.LogAllEvents {
					store.logger.Print().Msgf("[%v] %v\n", aurora.Yellow("WRN").String(), err.Error())
				}
				continue
			}

			store.logger.Warning().Msg(err.Error())
		}
	}

	templatesCache := store.parserCacheOnce()
	if templatesCache == nil {
		return errors.New("invalid parser")
	}

	loadedTemplateIDs := mapsutil.NewSyncLockMap[string, struct{}]()
	caps := templates.Capabilities{
		Headless:      store.config.ExecutorOptions.Options.Headless,
		Code:          store.config.ExecutorOptions.Options.EnableCodeTemplates,
		DAST:          store.config.ExecutorOptions.Options.DAST,
		SelfContained: store.config.ExecutorOptions.Options.EnableSelfContainedTemplates,
		File:          store.config.ExecutorOptions.Options.EnableFileTemplates,
	}
	isListOrDisplay := store.config.ExecutorOptions.Options.TemplateList ||
		store.config.ExecutorOptions.Options.TemplateDisplay

	for templatePath := range validPaths {
		template, _, _ := templatesCache.Has(templatePath)
		if template == nil {
			continue
		}

		if !isListOrDisplay && !template.IsEnabledFor(caps) {
			continue
		}

		if loadedTemplateIDs.Has(template.ID) {
			store.logger.Debug().Msgf("Skipping duplicate template ID '%s' from path '%s'", template.ID, templatePath)
			continue
		}

		_ = loadedTemplateIDs.Set(template.ID, struct{}{})
		template.Path = templatePath
		store.templates = append(store.templates, template)
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

	templatePathsMap := make(map[string]struct{}, len(templatePaths))
	for _, path := range templatePaths {
		templatePathsMap[path] = struct{}{}
	}

	workflowPathsMap := make(map[string]struct{}, len(workflowPaths))
	for _, path := range workflowPaths {
		workflowPathsMap[path] = struct{}{}
	}

	if store.areTemplatesValid(templatePathsMap) && store.areWorkflowsValid(workflowPathsMap) {
		return nil
	}

	return errors.New("errors occurred during template validation")
}

func (store *Store) areWorkflowsValid(filteredWorkflowPaths map[string]struct{}) bool {
	return store.areWorkflowOrTemplatesValid(filteredWorkflowPaths, true, func(templatePath string, tagFilter *templates.TagFilter) (bool, error) {
		return store.config.ExecutorOptions.Parser.LoadWorkflow(templatePath, store.config.Catalog)
	})
}

func (store *Store) areTemplatesValid(filteredTemplatePaths map[string]struct{}) bool {
	return store.areWorkflowOrTemplatesValid(filteredTemplatePaths, false, func(templatePath string, tagFilter *templates.TagFilter) (bool, error) {
		return store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
	})
}

func (store *Store) areWorkflowOrTemplatesValid(filteredTemplatePaths map[string]struct{}, isWorkflow bool, load func(templatePath string, tagFilter *templates.TagFilter) (bool, error)) bool {
	areTemplatesValid := true
	parsedCache := store.parserCacheOnce()

	for templatePath := range filteredTemplatePaths {
		if _, err := load(templatePath, store.tagFilter); err != nil {
			if isParsingError(store, "Error occurred loading template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
				continue
			}
		}

		var template *templates.Template
		var err error

		if parsedCache != nil {
			if cachedTemplate, _, cacheErr := parsedCache.Has(templatePath); cacheErr == nil && cachedTemplate != nil {
				template = cachedTemplate
			}
		}

		if template == nil {
			template, err = templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				if isParsingError(store, "Error occurred parsing template %s: %s\n", templatePath, err) {
					areTemplatesValid = false
					continue
				}
			}
		}

		if template == nil {
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
				store.logger.Warning().Msgf("Found duplicate template ID during validation '%s' => '%s': %s\n", templatePath, existingTemplatePath, template.ID)
			}

			if !isWorkflow && template.HasWorkflows() {
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
			if isParsingError(store, "Error occurred loading template %s: %s\n", workflow.Template, err) {
				return false
			}
		}
	}

	return true
}

func isParsingError(store *Store, message string, template string, err error) bool {
	if errors.Is(err, templates.ErrExcluded) {
		return false
	}

	if errors.Is(err, templates.ErrCreateTemplateExecutor) {
		return false
	}

	store.logger.Error().Msgf(message, template, err)

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

	loadedWorkflows := make([]*templates.Template, 0, len(includedWorkflows))
	for _, workflowPath := range includedWorkflows {
		loaded, err := store.config.ExecutorOptions.Parser.LoadWorkflow(workflowPath, store.config.Catalog)
		if err != nil {
			store.logger.Warning().Msgf("Could not load workflow %s: %s\n", workflowPath, err)
		}

		if loaded {
			parsed, err := templates.Parse(workflowPath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				store.logger.Warning().Msgf("Could not parse workflow %s: %s\n", workflowPath, err)
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
	defer store.saveMetadataIndexOnce()

	indexFilter := store.indexFilter

	includedTemplates, errs := store.config.Catalog.GetTemplatesPath(templatesList)
	store.logErroredTemplates(errs)

	loadedTemplates := sliceutil.NewSyncSlice[*templates.Template]()
	loadedTemplateIDs := mapsutil.NewSyncLockMap[string, struct{}]()

	loadTemplate := func(tmpl *templates.Template) {
		if loadedTemplateIDs.Has(tmpl.ID) {
			store.logger.Debug().Msgf("Skipping duplicate template ID '%s' from path '%s'", tmpl.ID, tmpl.Path)
			return
		}

		_ = loadedTemplateIDs.Set(tmpl.ID, struct{}{})

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

	typesOpts := store.config.ExecutorOptions.Options
	concurrency := typesOpts.TemplateLoadingConcurrency
	if concurrency <= 0 {
		concurrency = types.DefaultTemplateLoadingConcurrency
	}

	wgLoadTemplates, errWg := syncutil.New(syncutil.WithSize(concurrency))
	if errWg != nil {
		panic("could not create wait group")
	}

	if typesOpts.ExecutionId == "" {
		typesOpts.ExecutionId = xid.New().String()
	}

	dialers := protocolstate.GetDialersWithId(typesOpts.ExecutionId)
	if dialers == nil {
		panic("dialers with executionId " + typesOpts.ExecutionId + " not found")
	}

	for _, templatePath := range includedTemplates {
		wgLoadTemplates.Add()
		go func(templatePath string) {
			defer wgLoadTemplates.Done()

			var (
				metadata       *index.Metadata
				metadataCached bool
			)

			if store.metadataIndex != nil {
				if cachedMetadata, found := store.metadataIndex.Get(templatePath); found {
					metadata = cachedMetadata
					if !indexFilter.Matches(metadata) {
						return
					}
					// NOTE(dwisiswant0): else, tagFilter probably exists (for
					// IncludeConditions), which still need to check via
					// LoadTemplate.

					metadataCached = true
				}
			}

			loaded, err := store.config.ExecutorOptions.Parser.LoadTemplate(templatePath, store.tagFilter, tags, store.config.Catalog)
			if loaded {
				parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)

				if parsed != nil && !metadataCached {
					if store.metadataIndex != nil {
						metadata, _ = store.metadataIndex.SetFromTemplate(templatePath, parsed)
					} else {
						metadata = index.NewMetadataFromTemplate(templatePath, parsed)
					}

					if metadata != nil && !indexFilter.Matches(metadata) {
						return
					}
				}

				if err != nil {
					// exclude templates not compatible with offline matching from total runtime warning stats
					if !errors.Is(err, templates.ErrIncompatibleWithOfflineMatching) {
						stats.Increment(templates.RuntimeWarningsStats)
					}
					store.logger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
				} else if parsed != nil {
					if !parsed.Verified && typesOpts.DisableUnsignedTemplates {
						// skip unverified templates when prompted to
						stats.Increment(templates.SkippedUnsignedStats)
						return
					}

					if parsed.SelfContained && !typesOpts.EnableSelfContainedTemplates {
						stats.Increment(templates.ExcludedSelfContainedStats)
						return
					}

					if parsed.HasFileRequest() && !typesOpts.EnableFileTemplates {
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
					if store.ID() != AuthStoreId && typesOpts.DAST {
						// check if the template is a DAST template
						// also allow global matchers template to be loaded
						if parsed.IsFuzzableRequest() || parsed.IsGlobalMatchersTemplate() {
							if parsed.HasHeadlessRequest() && !typesOpts.Headless {
								stats.Increment(templates.ExcludedHeadlessTmplStats)
								if config.DefaultConfig.LogAllEvents {
									store.logger.Print().Msgf("[%v] Headless flag is required for headless template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
								}
							} else {
								loadTemplate(parsed)
							}
						}
					} else if parsed.HasHeadlessRequest() && !typesOpts.Headless {
						// donot include headless template in final list if headless flag is not set
						stats.Increment(templates.ExcludedHeadlessTmplStats)
						if config.DefaultConfig.LogAllEvents {
							store.logger.Print().Msgf("[%v] Headless flag is required for headless template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if parsed.HasCodeRequest() && !typesOpts.EnableCodeTemplates {
						// donot include 'Code' protocol custom template in final list if code flag is not set
						stats.Increment(templates.ExcludedCodeTmplStats)
						if config.DefaultConfig.LogAllEvents {
							store.logger.Print().Msgf("[%v] Code flag is required for code protocol template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if parsed.HasCodeRequest() && !parsed.Verified && !parsed.HasWorkflows() {
						// donot include unverified 'Code' protocol custom template in final list
						stats.Increment(templates.SkippedCodeTmplTamperedStats)
						// these will be skipped so increment skip counter
						stats.Increment(templates.SkippedUnsignedStats)
						if config.DefaultConfig.LogAllEvents {
							store.logger.Print().Msgf("[%v] Tampered/Unsigned template at %v.\n", aurora.Yellow("WRN").String(), templatePath)
						}
					} else if parsed.IsFuzzableRequest() && !typesOpts.DAST {
						stats.Increment(templates.ExludedDastTmplStats)
						if config.DefaultConfig.LogAllEvents {
							store.logger.Print().Msgf("[%v] -dast flag is required for DAST template '%s'.\n", aurora.Yellow("WRN").String(), templatePath)
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
						store.logger.Print().Msgf("[%v] %v\n", aurora.Yellow("WRN").String(), err.Error())
					}
					return
				}
				store.logger.Warning().Msg(err.Error())
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
		if template.HasHTTPRequest() || template.HasHeadlessRequest() {
			return true
		}

		if template.HasWorkflows() {
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
			s.logger.Error().Msgf("Could not find template '%s': %s", template, err)
		}
	}
}
