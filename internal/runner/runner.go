package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/pdcp"
	"github.com/projectdiscovery/nuclei/v3/internal/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/parser"
	outputstats "github.com/projectdiscovery/nuclei/v3/pkg/output/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan/events"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	uncoverlib "github.com/projectdiscovery/uncover"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	permissionutil "github.com/projectdiscovery/utils/permission"
	pprofutil "github.com/projectdiscovery/utils/pprof"
	updateutils "github.com/projectdiscovery/utils/update"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v3/internal/httpapi"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/external/customtemplates"
	fuzzStats "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	parsers "github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/automaticscan"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/excludematchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	httpProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/retryablehttp-go"
	ptrutil "github.com/projectdiscovery/utils/ptr"
)

var (
	// HideAutoSaveMsg is a global variable to hide the auto-save message
	HideAutoSaveMsg = false
	// EnableCloudUpload is global variable to enable cloud upload
	EnableCloudUpload = false
)

// Runner is a client for running the enumeration process.
type Runner struct {
	output             output.Writer
	interactsh         *interactsh.Client
	options            *types.Options
	projectFile        *projectfile.ProjectFile
	catalog            catalog.Catalog
	progress           progress.Progress
	colorizer          aurora.Aurora
	issuesClient       reporting.Client
	browser            *engine.Browser
	rateLimiter        *ratelimit.Limiter
	hostErrors         hosterrorscache.CacheInterface
	resumeCfg          *types.ResumeCfg
	pprofServer        *pprofutil.PprofServer
	pdcpUploadErrMsg   string
	inputProvider      provider.InputProvider
	fuzzFrequencyCache *frequency.Tracker
	httpStats          *outputstats.Tracker

	//general purpose temporary directory
	tmpDir          string
	parser          parser.Parser
	httpApiEndpoint *httpapi.Server
	fuzzStats       *fuzzStats.Tracker
	dastServer      *server.DASTServer
}

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options))
		os.Exit(0)
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

	parser := templates.NewParser()

	if options.Validate {
		parser.ShouldValidate = true
	}
	// TODO: refactor to pass options reference globally without cycles
	parser.NoStrictSyntax = options.NoStrictSyntax
	runner.parser = parser

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
	if options.ProxyInternal && options.AliveHttpProxy != "" || options.AliveSocksProxy != "" {
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
		client, err := reporting.New(reportingOptions, options.ReportingDB, false)
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
		runner.pprofServer = pprofutil.NewPprofServer()
		runner.pprofServer.Start()
	}

	if options.HttpApiEndpoint != "" {
		apiServer := httpapi.New(options.HttpApiEndpoint, options)
		gologger.Info().Msgf("Listening api endpoint on: %s", options.HttpApiEndpoint)
		runner.httpApiEndpoint = apiServer
		go func() {
			if err := apiServer.Start(); err != nil {
				gologger.Error().Msgf("Failed to start API server: %s", err)
			}
		}()
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.TargetsFilePath == "" && !options.Stdin && len(options.Targets) == 0)) && options.UpdateTemplates {
		os.Exit(0)
	}

	// create the input provider and load the inputs
	inputProvider, err := provider.NewInputProvider(provider.InputOptions{Options: options})
	if err != nil {
		return nil, errors.Wrap(err, "could not create input provider")
	}
	runner.inputProvider = inputProvider

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	// setup a proxy writer to automatically upload results to PDCP
	runner.output = runner.setupPDCPUpload(outputWriter)
	if options.HTTPStats {
		runner.httpStats = outputstats.NewTracker()
		runner.output = output.NewMultiWriter(runner.output, output.NewTrackerWriter(runner.httpStats))
	}

	if options.JSONL && options.EnableProgressBar {
		options.StatsJSON = true
	}
	if options.StatsJSON {
		options.EnableProgressBar = true
	}
	// Creates the progress tracking object
	var progressErr error
	statsInterval := options.StatsInterval
	runner.progress, progressErr = progress.NewStatsTicker(statsInterval, options.EnableProgressBar, options.StatsJSON, false, options.MetricsPort)
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

	if options.DASTReport || options.DASTServer {
		var err error
		runner.fuzzStats, err = fuzzStats.NewTracker()
		if err != nil {
			return nil, errors.Wrap(err, "could not create fuzz stats db")
		}
		if !options.DASTServer {
			dastServer, err := server.NewStatsServer(runner.fuzzStats)
			if err != nil {
				return nil, errors.Wrap(err, "could not create dast server")
			}
			runner.dastServer = dastServer
		}
	}

	if runner.fuzzStats != nil {
		outputWriter.JSONLogRequestHook = func(request *output.JSONLogRequest) {
			if request.Error == "none" || request.Error == "" {
				return
			}
			runner.fuzzStats.RecordErrorEvent(fuzzStats.ErrorEvent{
				TemplateID: request.Template,
				URL:        request.Input,
				Error:      request.Error,
			})
		}
	}

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
		gologger.Print().Msgf("[%v] %v", aurora.BrightYellow("WRN"), "rate limit per minute is deprecated - use rate-limit-duration")
		options.RateLimit = options.RateLimitMinute
		options.RateLimitDuration = time.Minute
	}
	if options.RateLimit > 0 && options.RateLimitDuration == 0 {
		options.RateLimitDuration = time.Second
	}
	if options.RateLimit == 0 && options.RateLimitDuration == 0 {
		runner.rateLimiter = ratelimit.NewUnlimited(context.Background())
	} else {
		runner.rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit), options.RateLimitDuration)
	}

	if tmpDir, err := os.MkdirTemp("", "nuclei-tmp-*"); err == nil {
		runner.tmpDir = tmpDir
	}

	return runner, nil
}

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecutorOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.dastServer != nil {
		r.dastServer.Close()
	}
	if r.httpStats != nil {
		r.httpStats.DisplayTopStats(r.options.NoColor)
	}
	// dump hosterrors cache
	if r.hostErrors != nil {
		r.hostErrors.Close()
	}
	if r.output != nil {
		r.output.Close()
	}
	if r.issuesClient != nil {
		r.issuesClient.Close()
	}
	if r.projectFile != nil {
		r.projectFile.Close()
	}
	if r.inputProvider != nil {
		r.inputProvider.Close()
	}
	protocolinit.Close()
	if r.pprofServer != nil {
		r.pprofServer.Stop()
	}
	if r.rateLimiter != nil {
		r.rateLimiter.Stop()
	}
	r.progress.Stop()
	if r.browser != nil {
		r.browser.Close()
	}
	if r.tmpDir != "" {
		_ = os.RemoveAll(r.tmpDir)
	}

	//this is no-op unless nuclei is built with stats build tag
	events.Close()
}

// setupPDCPUpload sets up the PDCP upload writer
// by creating a new writer and returning it
func (r *Runner) setupPDCPUpload(writer output.Writer) output.Writer {
	// if scanid is given implicitly consider that scan upload is enabled
	if r.options.ScanID != "" {
		r.options.EnableCloudUpload = true
	}
	if !(r.options.EnableCloudUpload || EnableCloudUpload) {
		r.pdcpUploadErrMsg = fmt.Sprintf("[%v] Scan results upload to cloud is disabled.", r.colorizer.BrightYellow("WRN"))
		return writer
	}
	color := aurora.NewAurora(!r.options.NoColor)
	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		if err != pdcpauth.ErrNoCreds && !HideAutoSaveMsg {
			gologger.Verbose().Msgf("Could not get credentials for cloud upload: %s\n", err)
		}
		r.pdcpUploadErrMsg = fmt.Sprintf("[%v] To view results on Cloud Dashboard, Configure API key from %v", color.BrightYellow("WRN"), pdcpauth.DashBoardURL)
		return writer
	}
	uploadWriter, err := pdcp.NewUploadWriter(context.Background(), creds)
	if err != nil {
		r.pdcpUploadErrMsg = fmt.Sprintf("[%v] PDCP (%v) Auto-Save Failed: %s\n", color.BrightYellow("WRN"), pdcpauth.DashBoardURL, err)
		return writer
	}
	if r.options.ScanID != "" {
		// ignore and use empty scan id if invalid
		_ = uploadWriter.SetScanID(r.options.ScanID)
	}
	if r.options.ScanName != "" {
		uploadWriter.SetScanName(r.options.ScanName)
	}
	if r.options.TeamID != "" {
		uploadWriter.SetTeamID(r.options.TeamID)
	}
	return output.NewMultiWriter(writer, uploadWriter)
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() error {
	// If the user has asked for DAST server mode, run the live
	// DAST fuzzing server.
	if r.options.DASTServer {
		execurOpts := &server.NucleiExecutorOptions{
			Options:            r.options,
			Output:             r.output,
			Progress:           r.progress,
			Catalog:            r.catalog,
			IssuesClient:       r.issuesClient,
			RateLimiter:        r.rateLimiter,
			Interactsh:         r.interactsh,
			ProjectFile:        r.projectFile,
			Browser:            r.browser,
			Colorizer:          r.colorizer,
			Parser:             r.parser,
			TemporaryDirectory: r.tmpDir,
			FuzzStatsDB:        r.fuzzStats,
		}
		dastServer, err := server.New(&server.Options{
			Address:               r.options.DASTServerAddress,
			Templates:             r.options.Templates,
			OutputWriter:          r.output,
			Verbose:               r.options.Verbose,
			Token:                 r.options.DASTServerToken,
			InScope:               r.options.Scope,
			OutScope:              r.options.OutOfScope,
			NucleiExecutorOptions: execurOpts,
		})
		if err != nil {
			return err
		}
		r.dastServer = dastServer
		return dastServer.Start()
	}

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

	fuzzFreqCache := frequency.New(frequency.DefaultMaxTrackCount, r.options.FuzzParamFrequency)
	r.fuzzFrequencyCache = fuzzFreqCache

	// Create the executor options which will be used throughout the execution
	// stage by the nuclei engine modules.
	executorOpts := protocols.ExecutorOptions{
		Output:              r.output,
		Options:             r.options,
		Progress:            r.progress,
		Catalog:             r.catalog,
		IssuesClient:        r.issuesClient,
		RateLimiter:         r.rateLimiter,
		Interactsh:          r.interactsh,
		ProjectFile:         r.projectFile,
		Browser:             r.browser,
		Colorizer:           r.colorizer,
		ResumeCfg:           r.resumeCfg,
		ExcludeMatchers:     excludematchers.New(r.options.ExcludeMatchers),
		InputHelper:         input.NewHelper(),
		TemporaryDirectory:  r.tmpDir,
		Parser:              r.parser,
		FuzzParamsFrequency: fuzzFreqCache,
		GlobalMatchers:      globalmatchers.New(),
	}

	if config.DefaultConfig.IsDebugArgEnabled(config.DebugExportURLPattern) {
		// Go StdLib style experimental/debug feature switch
		executorOpts.ExportReqURLPattern = true
	}

	if len(r.options.SecretsFile) > 0 && !r.options.Validate {
		authTmplStore, err := GetAuthTmplStore(*r.options, r.catalog, executorOpts)
		if err != nil {
			return errors.Wrap(err, "failed to load dynamic auth templates")
		}
		authOpts := &authprovider.AuthProviderOptions{SecretsFiles: r.options.SecretsFile}
		authOpts.LazyFetchSecret = GetLazyAuthFetchCallback(&AuthLazyFetchOptions{
			TemplateStore: authTmplStore,
			ExecOpts:      executorOpts,
		})
		// initialize auth provider
		provider, err := authprovider.NewAuthProvider(authOpts)
		if err != nil {
			return errors.Wrap(err, "could not create auth provider")
		}
		executorOpts.AuthProvider = provider
	}

	if r.options.ShouldUseHostError() {
		maxHostError := r.options.MaxHostError
		if r.options.TemplateThreads > maxHostError {
			gologger.Print().Msgf("[%v] The concurrency value is higher than max-host-error", r.colorizer.BrightYellow("WRN"))
			gologger.Info().Msgf("Adjusting max-host-error to the concurrency value: %d", r.options.TemplateThreads)

			maxHostError = r.options.TemplateThreads
		}

		cache := hosterrorscache.New(maxHostError, hosterrorscache.DefaultMaxHostsCount, r.options.TrackError)
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

	// If using input-file flags, only load http fuzzing based templates.
	loaderConfig := loader.NewConfig(r.options, r.catalog, executorOpts)
	if !strings.EqualFold(r.options.InputFileMode, "list") || r.options.DAST {
		// if input type is not list (implicitly enable fuzzing)
		r.options.DAST = true
	}
	store, err := loader.New(loaderConfig)
	if err != nil {
		return errors.Wrap(err, "Could not create loader.")
	}

	// list all templates or tags as specified by user.
	// This uses a separate parser to reduce time taken as
	// normally nuclei does a lot of compilation and stuff
	// for templates, which we don't want for these simp
	if r.options.TemplateList || r.options.TemplateDisplay || r.options.TagList {
		if err := store.LoadTemplatesOnlyMetadata(); err != nil {
			return err
		}

		if r.options.TagList {
			r.listAvailableStoreTags(store)
		} else {
			r.listAvailableStoreTemplates(store)
		}
		os.Exit(0)
	}

	if r.options.Validate {
		if err := store.ValidateTemplates(); err != nil {
			return err
		}
		if stats.GetValue(templates.SyntaxErrorStats) == 0 && stats.GetValue(templates.SyntaxWarningStats) == 0 && stats.GetValue(templates.RuntimeWarningsStats) == 0 {
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
			_ = r.inputProvider.SetWithExclusions(host)
		}
	}
	// display execution info like version , templates used etc
	r.displayExecutionInfo(store)

	// prefetch secrets if enabled
	if executorOpts.AuthProvider != nil && r.options.PreFetchSecrets {
		gologger.Info().Msgf("Pre-fetching secrets from authprovider[s]")
		if err := executorOpts.AuthProvider.PreFetchSecrets(); err != nil {
			return errors.Wrap(err, "could not pre-fetch secrets")
		}
	}

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

	// initialize stats worker ( this is no-op unless nuclei is built with stats build tag)
	// during execution a directory with 2 files will be created in the current directory
	// config.json - containing below info
	// events.jsonl - containing all start and end times of all templates
	events.InitWithConfig(&events.ScanConfig{
		Name:                "nuclei-stats", // make this configurable
		TargetCount:         int(r.inputProvider.Count()),
		TemplatesCount:      len(store.Templates()) + len(store.Workflows()),
		TemplateConcurrency: r.options.TemplateThreads,
		PayloadConcurrency:  r.options.PayloadConcurrency,
		JsConcurrency:       r.options.JsConcurrency,
		Retries:             r.options.Retries,
	}, "")

	if r.dastServer != nil {
		go func() {
			if err := r.dastServer.Start(); err != nil {
				gologger.Error().Msgf("could not start dast server: %v", err)
			}
		}()
	}

	enumeration := false
	var results *atomic.Bool
	results, err = r.runStandardEnumeration(executorOpts, store, executorEngine)
	enumeration = true

	if !enumeration {
		return err
	}

	if executorOpts.FuzzStatsDB != nil {
		executorOpts.FuzzStatsDB.Close()
	}
	if r.interactsh != nil {
		matched := r.interactsh.Close()
		if matched {
			results.CompareAndSwap(false, true)
		}
	}
	if executorOpts.InputHelper != nil {
		_ = executorOpts.InputHelper.Close()
	}
	r.fuzzFrequencyCache.Close()

	// todo: error propagation without canonical straight error check is required by cloud?
	// use safe dereferencing to avoid potential panics in case of previous unchecked errors
	if v := ptrutil.Safe(results); !v.Load() {
		gologger.Info().Msgf("No results found. Better luck next time!")
	}
	// check if a passive scan was requested but no target was provided
	if r.options.OfflineHTTP && len(r.options.Targets) == 0 && r.options.TargetsFilePath == "" {
		return errors.Wrap(err, "missing required input (http response) to run passive templates")
	}

	return err
}

func (r *Runner) isInputNonHTTP() bool {
	var nonURLInput bool
	r.inputProvider.Iterate(func(value *contextargs.MetaInput) bool {
		if !strings.Contains(value.Input, "://") {
			nonURLInput = true
			return false
		}
		return true
	})
	return nonURLInput
}

func (r *Runner) executeSmartWorkflowInput(executorOpts protocols.ExecutorOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	r.progress.Init(r.inputProvider.Count(), 0, 0)

	service, err := automaticscan.New(automaticscan.Options{
		ExecuterOpts: executorOpts,
		Store:        store,
		Engine:       engine,
		Target:       r.inputProvider,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create automatic scan service")
	}
	if err := service.Execute(); err != nil {
		return nil, errors.Wrap(err, "could not execute automatic scan")
	}
	result := &atomic.Bool{}
	result.Store(service.Close())
	return result, nil
}

func (r *Runner) executeTemplatesInput(store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.VerboseVerbose {
		for _, template := range store.Templates() {
			r.logAvailableTemplate(template.Path)
		}
		for _, template := range store.Workflows() {
			r.logAvailableTemplate(template.Path)
		}
	}

	finalTemplates := []*templates.Template{}
	finalTemplates = append(finalTemplates, store.Templates()...)
	finalTemplates = append(finalTemplates, store.Workflows()...)

	if len(finalTemplates) == 0 {
		return nil, errors.New("no templates provided for scan")
	}

	// pass input provider to engine
	// TODO: this should be not necessary after r.hmapInputProvider is removed + refactored
	if r.inputProvider == nil {
		return nil, errors.New("no input provider found")
	}
	results := engine.ExecuteScanWithOpts(context.Background(), finalTemplates, r.inputProvider, r.options.DisableClustering)
	return results, nil
}

// displayExecutionInfo displays misc info about the nuclei engine execution
func (r *Runner) displayExecutionInfo(store *loader.Store) {
	// Display stats for any loaded templates' syntax warnings or errors
	stats.Display(templates.SyntaxWarningStats)
	stats.Display(templates.SyntaxErrorStats)
	stats.Display(templates.RuntimeWarningsStats)
	tmplCount := len(store.Templates())
	workflowCount := len(store.Workflows())
	if r.options.Verbose || (tmplCount == 0 && workflowCount == 0) {
		// only print these stats in verbose mode
		stats.ForceDisplayWarning(templates.ExcludedHeadlessTmplStats)
		stats.ForceDisplayWarning(templates.ExcludedCodeTmplStats)
		stats.ForceDisplayWarning(templates.ExludedDastTmplStats)
		stats.ForceDisplayWarning(templates.TemplatesExcludedStats)
		stats.ForceDisplayWarning(templates.ExcludedFileStats)
		stats.ForceDisplayWarning(templates.ExcludedSelfContainedStats)
	}

	if tmplCount == 0 && workflowCount == 0 {
		// if dast flag is used print explicit warning
		if r.options.DAST {
			gologger.DefaultLogger.Print().Msgf("[%v] No DAST templates found", aurora.BrightYellow("WRN"))
		}
		stats.ForceDisplayWarning(templates.SkippedCodeTmplTamperedStats)
	} else {
		stats.DisplayAsWarning(templates.SkippedCodeTmplTamperedStats)
	}
	stats.DisplayAsWarning(httpProtocol.SetThreadToCountZero)
	stats.ForceDisplayWarning(templates.SkippedUnsignedStats)
	stats.ForceDisplayWarning(templates.SkippedRequestSignatureStats)

	cfg := config.DefaultConfig

	updateutils.Aurora = r.colorizer
	gologger.Info().Msgf("Current nuclei version: %v %v", config.Version, updateutils.GetVersionDescription(config.Version, cfg.LatestNucleiVersion))
	gologger.Info().Msgf("Current nuclei-templates version: %v %v", cfg.TemplateVersion, updateutils.GetVersionDescription(cfg.TemplateVersion, cfg.LatestNucleiTemplatesVersion))
	if !HideAutoSaveMsg {
		if r.pdcpUploadErrMsg != "" {
			gologger.Print().Msgf("%s", r.pdcpUploadErrMsg)
		} else {
			gologger.Info().Msgf("To view results on cloud dashboard, visit %v/scans upon scan completion.", pdcpauth.DashBoardURL)
		}
	}

	if tmplCount > 0 || workflowCount > 0 {
		if len(store.Templates()) > 0 {
			gologger.Info().Msgf("New templates added in latest release: %d", len(config.DefaultConfig.GetNewAdditions()))
			gologger.Info().Msgf("Templates loaded for current scan: %d", len(store.Templates()))
		}
		if len(store.Workflows()) > 0 {
			gologger.Info().Msgf("Workflows loaded for current scan: %d", len(store.Workflows()))
		}
		for k, v := range templates.SignatureStats {
			value := v.Load()
			if value > 0 {
				if k == templates.Unsigned && !r.options.Silent && !config.DefaultConfig.HideTemplateSigWarning {
					gologger.Print().Msgf("[%v] Loading %d unsigned templates for scan. Use with caution.", r.colorizer.BrightYellow("WRN"), value)
				} else {
					gologger.Info().Msgf("Executing %d signed templates from %s", value, k)
				}
			}
		}
	}

	if r.inputProvider.Count() > 0 {
		gologger.Info().Msgf("Targets loaded for current scan: %d", r.inputProvider.Count())
	}
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig(path string) error {
	dir := filepath.Dir(path)
	if !fileutil.FolderExists(dir) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}
	resumeCfgClone := r.resumeCfg.Clone()
	resumeCfgClone.ResumeFrom = resumeCfgClone.Current
	data, _ := json.MarshalIndent(resumeCfgClone, "", "\t")

	return os.WriteFile(path, data, permissionutil.ConfigFilePermission)
}

// upload existing scan results to cloud with progress
func UploadResultsToCloud(options *types.Options) error {
	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		return errors.Wrap(err, "could not get credentials for cloud upload")
	}
	ctx := context.TODO()
	uploadWriter, err := pdcp.NewUploadWriter(ctx, creds)
	if err != nil {
		return errors.Wrap(err, "could not create upload writer")
	}
	if options.ScanID != "" {
		_ = uploadWriter.SetScanID(options.ScanID)
	}
	if options.ScanName != "" {
		uploadWriter.SetScanName(options.ScanName)
	}
	if options.TeamID != "" {
		uploadWriter.SetTeamID(options.TeamID)
	}

	// Open file to count the number of results first
	file, err := os.Open(options.ScanUploadFile)
	if err != nil {
		return errors.Wrap(err, "could not open scan upload file")
	}
	defer file.Close()

	gologger.Info().Msgf("Uploading scan results to cloud dashboard from %s", options.ScanUploadFile)
	dec := json.NewDecoder(file)
	for dec.More() {
		var r output.ResultEvent
		err := dec.Decode(&r)
		if err != nil {
			gologger.Warning().Msgf("Could not decode jsonl: %s\n", err)
			continue
		}
		if err = uploadWriter.Write(&r); err != nil {
			gologger.Warning().Msgf("[%s] failed to upload: %s\n", r.TemplateID, err)
		}
	}
	uploadWriter.Close()
	return nil
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

func init() {
	HideAutoSaveMsg = env.GetEnvOrDefault("DISABLE_CLOUD_UPLOAD_WRN", false)
	EnableCloudUpload = env.GetEnvOrDefault("ENABLE_CLOUD_UPLOAD", false)
}
