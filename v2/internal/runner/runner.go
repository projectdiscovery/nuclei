package runner

import (
	"context"
	"encoding/json"
	"net/http"
	_ "net/http/pprof"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v2/internal/installer"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	uncoverlib "github.com/projectdiscovery/uncover"
	permissionutil "github.com/projectdiscovery/utils/permission"
	updateutils "github.com/projectdiscovery/utils/update"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/hybrid"
	"github.com/projectdiscovery/nuclei/v2/pkg/external/customtemplates"
	"github.com/projectdiscovery/nuclei/v2/pkg/input"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/automaticscan"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/excludematchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/jsonexporter"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/jsonl"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	"github.com/projectdiscovery/retryablehttp-go"
	ptrutil "github.com/projectdiscovery/utils/ptr"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	interactsh        *interactsh.Client
	options           *types.Options
	projectFile       *projectfile.ProjectFile
	catalog           catalog.Catalog
	progress          progress.Progress
	colorizer         aurora.Aurora
	issuesClient      reporting.Client
	hmapInputProvider *hybrid.Input
	browser           *engine.Browser
	rateLimiter       *ratelimit.Limiter
	hostErrors        hosterrorscache.CacheInterface
	resumeCfg         *types.ResumeCfg
	pprofServer       *http.Server
	cloudClient       *nucleicloud.Client
	cloudTargets      []string
}

const pprofServerAddress = "127.0.0.1:8086"

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options))
		os.Exit(0)
	}

	if options.Cloud {
		runner.cloudClient = nucleicloud.New(options.CloudURL, options.CloudAPIKey)
	}

	//  Version check by default
	if config.DefaultConfig.CanCheckForUpdates() {
		if err := installer.NucleiVersionCheck(); err != nil {
			if options.Verbose || options.Debug {
				gologger.Error().Msgf("nuclei version check failed got: %s\n", err)
			}
		}

		// check for custom template updates and update if available
		ctm, err := customtemplates.NewCustomTemplatesManager(options)
		if err != nil {
			gologger.Error().Label("custom-templates").Msgf("Failed to create custom templates manager: %s\n", err)
		}

		// Check for template updates and update if available.
		// If the custom templates manager is not nil, we will install custom templates if there is a fresh installation
		tm := &installer.TemplateManager{
			CustomTemplates:        ctm,
			DisablePublicTemplates: options.PublicTemplateDisableDownload,
		}
		if err := tm.FreshInstallIfNotExists(); err != nil {
			gologger.Warning().Msgf("failed to install nuclei templates: %s\n", err)
		}
		if err := tm.UpdateIfOutdated(); err != nil {
			gologger.Warning().Msgf("failed to update nuclei templates: %s\n", err)
		}

		if config.DefaultConfig.NeedsIgnoreFileUpdate() {
			if err := installer.UpdateIgnoreFile(); err != nil {
				gologger.Warning().Msgf("failed to update nuclei ignore file: %s\n", err)
			}
		}

		if options.UpdateTemplates {
			// we automatically check for updates unless explicitly disabled
			// this print statement is only to inform the user that there are no updates
			if !config.DefaultConfig.NeedsTemplateUpdate() {
				gologger.Info().Msgf("No new updates found for nuclei templates")
			}
			// manually trigger update of custom templates
			if ctm != nil {
				ctm.Update(context.TODO())
			}
		}
	}

	if options.Validate {
		parsers.ShouldValidate = true
	}

	// TODO: refactor to pass options reference globally without cycles
	parsers.NoStrictSyntax = options.NoStrictSyntax
	yaml.StrictSyntax = !options.NoStrictSyntax

	if options.Headless {
		if engine.MustDisableSandbox() {
			gologger.Warning().Msgf("The current platform and privileged user will run the browser without sandbox\n")
		}
		browser, err := engine.New(options)
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}

	runner.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)

	var httpclient *retryablehttp.Client
	if options.ProxyInternal && types.ProxyURL != "" || types.ProxySocksURL != "" {
		var err error
		httpclient, err = httpclientpool.Get(options, &httpclientpool.Configuration{})
		if err != nil {
			return nil, err
		}
	}

	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return nil, err
	}
	reportingOptions, err := createReportingOptions(options)
	if err != nil {
		return nil, err
	}
	if reportingOptions != nil && httpclient != nil {
		reportingOptions.HttpClient = httpclient
	}

	if reportingOptions != nil {
		client, err := reporting.New(reportingOptions, options.ReportingDB)
		if err != nil {
			return nil, errors.Wrap(err, "could not create issue reporting client")
		}
		runner.issuesClient = client
	}

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	templates.Colorizer = runner.colorizer
	templates.SeverityColorizer = colorizer.New(runner.colorizer)

	if options.EnablePprof {
		server := &http.Server{
			Addr:    pprofServerAddress,
			Handler: http.DefaultServeMux,
		}
		gologger.Info().Msgf("Listening pprof debug server on: %s", pprofServerAddress)
		runner.pprofServer = server
		go func() {
			_ = server.ListenAndServe()
		}()
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.TargetsFilePath == "" && !options.Stdin && len(options.Targets) == 0)) && (options.UpdateTemplates && !options.Cloud) {
		os.Exit(0)
	}

	// Initialize the input source
	hmapInput, err := hybrid.New(&hybrid.Options{
		Options: options,
		NotFoundCallback: func(target string) bool {
			if !options.Cloud {
				return false
			}
			parsed, parseErr := strconv.ParseInt(target, 10, 64)
			if parseErr != nil {
				if err := runner.cloudClient.ExistsDataSourceItem(nucleicloud.ExistsDataSourceItemRequest{Contents: target, Type: "targets"}); err == nil {
					runner.cloudTargets = append(runner.cloudTargets, target)
					return true
				}
				return false
			}
			if exists, err := runner.cloudClient.ExistsTarget(parsed); err == nil {
				runner.cloudTargets = append(runner.cloudTargets, exists.Reference)
				return true
			}
			return false
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create input provider")
	}
	runner.hmapInputProvider = hmapInput

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	runner.output = outputWriter

	if options.JSONL && options.EnableProgressBar {
		options.StatsJSON = true
	}
	if options.StatsJSON {
		options.EnableProgressBar = true
	}
	// Creates the progress tracking object
	var progressErr error
	statsInterval := options.StatsInterval
	if options.Cloud && !options.EnableProgressBar {
		statsInterval = -1
		options.EnableProgressBar = true
	}
	runner.progress, progressErr = progress.NewStatsTicker(statsInterval, options.EnableProgressBar, options.StatsJSON, options.Metrics, options.Cloud, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load the existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: utils.IsBlank(options.ProjectPath)})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	// create the resume configuration structure
	resumeCfg := types.NewResumeCfg()
	if runner.options.ShouldLoadResume() {
		gologger.Info().Msg("Resuming from save checkpoint")
		file, err := os.ReadFile(runner.options.Resume)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(file, &resumeCfg)
		if err != nil {
			return nil, err
		}
		resumeCfg.Compile()
	}
	runner.resumeCfg = resumeCfg

	opts := interactsh.DefaultOptions(runner.output, runner.issuesClient, runner.progress)
	opts.Debug = runner.options.Debug
	opts.NoColor = runner.options.NoColor
	if options.InteractshURL != "" {
		opts.ServerURL = options.InteractshURL
	}
	opts.Authorization = options.InteractshToken
	opts.CacheSize = options.InteractionsCacheSize
	opts.Eviction = time.Duration(options.InteractionsEviction) * time.Second
	opts.CooldownPeriod = time.Duration(options.InteractionsCoolDownPeriod) * time.Second
	opts.PollDuration = time.Duration(options.InteractionsPollDuration) * time.Second
	opts.NoInteractsh = runner.options.NoInteractsh
	opts.StopAtFirstMatch = runner.options.StopAtFirstMatch
	opts.Debug = runner.options.Debug
	opts.DebugRequest = runner.options.DebugRequests
	opts.DebugResponse = runner.options.DebugResponse
	if httpclient != nil {
		opts.HTTPClient = httpclient
	}
	if opts.HTTPClient == nil {
		httpOpts := retryablehttp.DefaultOptionsSingle
		httpOpts.Timeout = 20 * time.Second // for stability reasons
		if options.Timeout > 20 {
			httpOpts.Timeout = time.Duration(options.Timeout) * time.Second
		}
		// in testing it was found most of times when interactsh failed, it was due to failure in registering /polling requests
		opts.HTTPClient = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	interactshClient, err := interactsh.New(opts)
	if err != nil {
		gologger.Error().Msgf("Could not create interactsh client: %s", err)
	} else {
		runner.interactsh = interactshClient
	}

	if options.RateLimitMinute > 0 {
		runner.rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	} else {
		runner.rateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	return runner, nil
}

func createReportingOptions(options *types.Options) (*reporting.Options, error) {
	var reportingOptions *reporting.Options
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not open reporting config file")
		}
		defer file.Close()

		reportingOptions = &reporting.Options{}
		if err := yaml.DecodeAndValidate(file, reportingOptions); err != nil {
			return nil, errors.Wrap(err, "could not parse reporting config file")
		}
		Walk(reportingOptions, expandEndVars)
	}
	if options.MarkdownExportDirectory != "" {
		if reportingOptions != nil {
			reportingOptions.MarkdownExporter = &markdown.Options{
				Directory:         options.MarkdownExportDirectory,
				IncludeRawPayload: !options.OmitRawRequests,
				SortMode:          options.MarkdownExportSortMode,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.MarkdownExporter = &markdown.Options{
				Directory:         options.MarkdownExportDirectory,
				IncludeRawPayload: !options.OmitRawRequests,
				SortMode:          options.MarkdownExportSortMode,
			}
		}
	}
	if options.SarifExport != "" {
		if reportingOptions != nil {
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		}
	}
	if options.JSONExport != "" {
		if reportingOptions != nil {
			reportingOptions.JSONExporter = &jsonexporter.Options{
				File:              options.JSONExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.JSONExporter = &jsonexporter.Options{
				File:              options.JSONExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		}
	}
	if options.JSONLExport != "" {
		if reportingOptions != nil {
			reportingOptions.JSONLExporter = &jsonl.Options{
				File:              options.JSONLExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.JSONLExporter = &jsonl.Options{
				File:              options.JSONLExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		}
	}

	return reportingOptions, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.output != nil {
		r.output.Close()
	}
	if r.projectFile != nil {
		r.projectFile.Close()
	}
	r.hmapInputProvider.Close()
	protocolinit.Close()
	if r.pprofServer != nil {
		_ = r.pprofServer.Shutdown(context.Background())
	}
	if r.rateLimiter != nil {
		r.rateLimiter.Stop()
	}
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() error {
	// If user asked for new templates to be executed, collect the list from the templates' directory.
	if r.options.NewTemplates {
		if arr := config.DefaultConfig.GetNewAdditions(); len(arr) > 0 {
			r.options.Templates = append(r.options.Templates, arr...)
		}
	}
	if len(r.options.NewTemplatesWithVersion) > 0 {
		if arr := installer.GetNewTemplatesInVersions(r.options.NewTemplatesWithVersion...); len(arr) > 0 {
			r.options.Templates = append(r.options.Templates, arr...)
		}
	}
	// Exclude ignored file for validation
	if !r.options.Validate {
		ignoreFile := config.ReadIgnoreFile()
		r.options.ExcludeTags = append(r.options.ExcludeTags, ignoreFile.Tags...)
		r.options.ExcludedTemplates = append(r.options.ExcludedTemplates, ignoreFile.Files...)
	}

	// Create the executor options which will be used throughout the execution
	// stage by the nuclei engine modules.
	executorOpts := protocols.ExecutorOptions{
		Output:          r.output,
		Options:         r.options,
		Progress:        r.progress,
		Catalog:         r.catalog,
		IssuesClient:    r.issuesClient,
		RateLimiter:     r.rateLimiter,
		Interactsh:      r.interactsh,
		ProjectFile:     r.projectFile,
		Browser:         r.browser,
		Colorizer:       r.colorizer,
		ResumeCfg:       r.resumeCfg,
		ExcludeMatchers: excludematchers.New(r.options.ExcludeMatchers),
		InputHelper:     input.NewHelper(),
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrorscache.New(r.options.MaxHostError, hosterrorscache.DefaultMaxHostsCount, r.options.TrackError)
		cache.SetVerbose(r.options.Verbose)
		r.hostErrors = cache
		executorOpts.HostErrorsCache = cache
	}

	executorEngine := core.New(r.options)
	executorEngine.SetExecuterOptions(executorOpts)

	workflowLoader, err := parsers.NewLoader(&executorOpts)
	if err != nil {
		return errors.Wrap(err, "Could not create loader.")
	}
	executorOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(r.options, r.catalog, executorOpts))
	if err != nil {
		return errors.Wrap(err, "could not load templates from config")
	}

	var cloudTemplates []string
	if r.options.Cloud {
		// hook template loading
		store.NotFoundCallback = func(template string) bool {
			parsed, parseErr := strconv.ParseInt(template, 10, 64)
			if parseErr != nil {
				if err := r.cloudClient.ExistsDataSourceItem(nucleicloud.ExistsDataSourceItemRequest{Type: "templates", Contents: template}); err == nil {
					cloudTemplates = append(cloudTemplates, template)
					return true
				}
				return false
			}
			if exists, err := r.cloudClient.ExistsTemplate(parsed); err == nil {
				cloudTemplates = append(cloudTemplates, exists.Reference)
				return true
			}
			return false
		}
	}
	if r.options.Validate {
		if err := store.ValidateTemplates(); err != nil {
			return err
		}
		if stats.GetValue(parsers.SyntaxErrorStats) == 0 && stats.GetValue(parsers.SyntaxWarningStats) == 0 && stats.GetValue(parsers.RuntimeWarningsStats) == 0 {
			gologger.Info().Msgf("All templates validated successfully\n")
		} else {
			return errors.New("encountered errors while performing template validation")
		}
		return nil // exit
	}
	store.Load()
	// TODO: remove below functions after v3 or update warning messages
	disk.PrintDeprecatedPathsMsgIfApplicable(r.options.Silent)
	templates.PrintDeprecatedProtocolNameMsgIfApplicable(r.options.Silent, r.options.Verbose)

	// add the hosts from the metadata queries of loaded templates into input provider
	if r.options.Uncover && len(r.options.UncoverQuery) == 0 {
		uncoverOpts := &uncoverlib.Options{
			Limit:         r.options.UncoverLimit,
			MaxRetry:      r.options.Retries,
			Timeout:       r.options.Timeout,
			RateLimit:     uint(r.options.UncoverRateLimit),
			RateLimitUnit: time.Minute, // default unit is minute
		}
		ret := uncover.GetUncoverTargetsFromMetadata(context.TODO(), store.Templates(), r.options.UncoverField, uncoverOpts)
		for host := range ret {
			r.hmapInputProvider.Set(host)
		}
	}
	// list all templates
	if r.options.TemplateList || r.options.TemplateDisplay {
		r.listAvailableStoreTemplates(store)
		os.Exit(0)
	}

	// display execution info like version , templates used etc
	r.displayExecutionInfo(store)

	// If not explicitly disabled, check if http based protocols
	// are used, and if inputs are non-http to pre-perform probing
	// of urls and storing them for execution.
	if !r.options.DisableHTTPProbe && loader.IsHTTPBasedProtocolUsed(store) && r.isInputNonHTTP() {
		inputHelpers, err := r.initializeTemplatesHTTPInput()
		if err != nil {
			return errors.Wrap(err, "could not probe http input")
		}
		executorOpts.InputHelper.InputsHTTP = inputHelpers
	}

	enumeration := false
	var results *atomic.Bool
	if r.options.Cloud {
		if r.options.ScanList {
			err = r.getScanList(r.options.OutputLimit)
		} else if r.options.DeleteScan != "" {
			err = r.deleteScan(r.options.DeleteScan)
		} else if r.options.ScanOutput != "" {
			err = r.getResults(r.options.ScanOutput, r.options.OutputLimit)
		} else if r.options.ListDatasources {
			err = r.listDatasources()
		} else if r.options.ListTargets {
			err = r.listTargets()
		} else if r.options.ListTemplates {
			err = r.listTemplates()
		} else if r.options.ListReportingSources {
			err = r.listReportingSources()
		} else if r.options.AddDatasource != "" {
			err = r.addCloudDataSource(r.options.AddDatasource)
		} else if r.options.RemoveDatasource != "" {
			err = r.removeDatasource(r.options.RemoveDatasource)
		} else if r.options.DisableReportingSource != "" {
			err = r.toggleReportingSource(r.options.DisableReportingSource, false)
		} else if r.options.EnableReportingSource != "" {
			err = r.toggleReportingSource(r.options.EnableReportingSource, true)
		} else if r.options.AddTarget != "" {
			err = r.addTarget(r.options.AddTarget)
		} else if r.options.AddTemplate != "" {
			err = r.addTemplate(r.options.AddTemplate)
		} else if r.options.GetTarget != "" {
			err = r.getTarget(r.options.GetTarget)
		} else if r.options.GetTemplate != "" {
			err = r.getTemplate(r.options.GetTemplate)
		} else if r.options.RemoveTarget != "" {
			err = r.removeTarget(r.options.RemoveTarget)
		} else if r.options.RemoveTemplate != "" {
			err = r.removeTemplate(r.options.RemoveTemplate)
		} else if r.options.ReportingConfig != "" {
			err = r.addCloudReportingSource()
		} else {
			if len(store.Templates())+len(store.Workflows())+len(cloudTemplates) == 0 {
				return errors.New("no templates provided for scan")
			}
			gologger.Info().Msgf("Running scan on cloud with URL %s", r.options.CloudURL)
			results, err = r.runCloudEnumeration(store, cloudTemplates, r.cloudTargets, r.options.NoStore, r.options.OutputLimit)
			enumeration = true
		}
	} else {
		results, err = r.runStandardEnumeration(executorOpts, store, executorEngine)
		enumeration = true
	}

	if !enumeration {
		return err
	}

	if r.interactsh != nil {
		matched := r.interactsh.Close()
		if matched {
			results.CompareAndSwap(false, true)
		}
	}
	r.progress.Stop()

	if executorOpts.InputHelper != nil {
		_ = executorOpts.InputHelper.Close()
	}
	if r.issuesClient != nil {
		r.issuesClient.Close()
	}

	// todo: error propagation without canonical straight error check is required by cloud?
	// use safe dereferencing to avoid potential panics in case of previous unchecked errors
	if v := ptrutil.Safe(results); !v.Load() {
		gologger.Info().Msgf("No results found. Better luck next time!")
	}
	if r.browser != nil {
		r.browser.Close()
	}
	// check if a passive scan was requested but no target was provided
	if r.options.OfflineHTTP && len(r.options.Targets) == 0 && r.options.TargetsFilePath == "" {
		return errors.Wrap(err, "missing required input (http response) to run passive templates")
	}

	return err
}

func (r *Runner) isInputNonHTTP() bool {
	var nonURLInput bool
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		if !strings.Contains(value.Input, "://") {
			nonURLInput = true
			return false
		}
		return true
	})
	return nonURLInput
}

func (r *Runner) executeSmartWorkflowInput(executorOpts protocols.ExecutorOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	r.progress.Init(r.hmapInputProvider.Count(), 0, 0)

	service, err := automaticscan.New(automaticscan.Options{
		ExecuterOpts: executorOpts,
		Store:        store,
		Engine:       engine,
		Target:       r.hmapInputProvider,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create automatic scan service")
	}
	service.Execute()
	result := &atomic.Bool{}
	result.Store(service.Close())
	return result, nil
}

func (r *Runner) executeTemplatesInput(store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	var unclusteredRequests int64
	for _, template := range store.Templates() {
		// workflows will dynamically adjust the totals while running, as
		// it can't be known in advance which requests will be called
		if len(template.Workflows) > 0 {
			continue
		}
		unclusteredRequests += int64(template.TotalRequests) * r.hmapInputProvider.Count()
	}

	if r.options.VerboseVerbose {
		for _, template := range store.Templates() {
			r.logAvailableTemplate(template.Path)
		}
		for _, template := range store.Workflows() {
			r.logAvailableTemplate(template.Path)
		}
	}

	// Cluster the templates first because we want info on how many
	// templates did we cluster for showing to user in CLI
	originalTemplatesCount := len(store.Templates())
	finalTemplates, clusterCount := templates.ClusterTemplates(store.Templates(), engine.ExecuterOptions())
	finalTemplates = append(finalTemplates, store.Workflows()...)

	var totalRequests int64
	for _, t := range finalTemplates {
		if len(t.Workflows) > 0 {
			continue
		}
		totalRequests += int64(t.Executer.Requests()) * r.hmapInputProvider.Count()
	}
	if totalRequests < unclusteredRequests {
		gologger.Info().Msgf("Templates clustered: %d (Reduced %d Requests)", clusterCount, unclusteredRequests-totalRequests)
	}
	workflowCount := len(store.Workflows())
	templateCount := originalTemplatesCount + workflowCount

	// 0 matches means no templates were found in the directory
	if templateCount == 0 {
		return &atomic.Bool{}, errors.New("no valid templates were found")
	}

	// tracks global progress and captures stdout/stderr until p.Wait finishes
	r.progress.Init(r.hmapInputProvider.Count(), templateCount, totalRequests)

	results := engine.ExecuteScanWithOpts(finalTemplates, r.hmapInputProvider, true)
	return results, nil
}

// displayExecutionInfo displays misc info about the nuclei engine execution
func (r *Runner) displayExecutionInfo(store *loader.Store) {
	// Display stats for any loaded templates' syntax warnings or errors
	stats.Display(parsers.SyntaxWarningStats)
	stats.Display(parsers.SyntaxErrorStats)
	stats.Display(parsers.RuntimeWarningsStats)

	cfg := config.DefaultConfig

	gologger.Info().Msgf("Current nuclei version: %v %v", config.Version, updateutils.GetVersionDescription(config.Version, cfg.LatestNucleiVersion))
	gologger.Info().Msgf("Current nuclei-templates version: %v %v", cfg.TemplateVersion, updateutils.GetVersionDescription(cfg.TemplateVersion, cfg.LatestNucleiTemplatesVersion))

	if len(store.Templates()) > 0 {
		gologger.Info().Msgf("New templates added in latest release: %d", len(config.DefaultConfig.GetNewAdditions()))
		gologger.Info().Msgf("Templates loaded for current scan: %d", len(store.Templates()))
	}
	if len(store.Workflows()) > 0 {
		gologger.Info().Msgf("Workflows loaded for current scan: %d", len(store.Workflows()))
	}
	if r.hmapInputProvider.Count() > 0 {
		gologger.Info().Msgf("Targets loaded for current scan: %d", r.hmapInputProvider.Count())
	}
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig(path string) error {
	resumeCfgClone := r.resumeCfg.Clone()
	resumeCfgClone.ResumeFrom = resumeCfgClone.Current
	data, _ := json.MarshalIndent(resumeCfgClone, "", "\t")

	return os.WriteFile(path, data, permissionutil.ConfigFilePermission)
}

type WalkFunc func(reflect.Value, reflect.StructField)

// Walk traverses a struct and executes a callback function on each value in the struct.
// The interface{} passed to the function should be a pointer to a struct or a struct.
// WalkFunc is the callback function used for each value in the struct. It is passed the
// reflect.Value and reflect.Type properties of the value in the struct.
func Walk(s interface{}, callback WalkFunc) {
	structValue := reflect.ValueOf(s)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Field(i)
		fieldType := structValue.Type().Field(i)
		if !fieldType.IsExported() {
			continue
		}
		if field.Kind() == reflect.Struct {
			Walk(field.Addr().Interface(), callback)
		} else if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			Walk(field.Interface(), callback)
		} else {
			callback(field, fieldType)
		}
	}
}

// expandEndVars looks for values in a struct tagged with "yaml" and checks if they are prefixed with '$'.
// If they are, it will try to retrieve the value from the environment and if it exists, it will set the
// value of the field to that of the environment variable.
func expandEndVars(f reflect.Value, fieldType reflect.StructField) {
	if _, ok := fieldType.Tag.Lookup("yaml"); !ok {
		return
	}
	if f.Kind() == reflect.String {
		str := f.String()
		if strings.HasPrefix(str, "$") {
			env := strings.TrimPrefix(str, "$")
			retrievedEnv := os.Getenv(env)
			if retrievedEnv != "" {
				f.SetString(os.Getenv(env))
			}
		}
	}
}
