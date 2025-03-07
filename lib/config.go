package nuclei

import (
	"context"
	"errors"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// TemplateSources contains template sources
// which define where to load templates from
type TemplateSources struct {
	Templates       []string // template file/directory paths
	Workflows       []string // workflow file/directory paths
	RemoteTemplates []string // remote template urls
	RemoteWorkflows []string // remote workflow urls
	TrustedDomains  []string // trusted domains for remote templates/workflows
}

// WithTemplatesOrWorkflows sets templates / workflows to use /load
func WithTemplatesOrWorkflows(sources TemplateSources) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		// by default all of these values are empty
		e.opts.Templates = sources.Templates
		e.opts.Workflows = sources.Workflows
		e.opts.TemplateURLs = sources.RemoteTemplates
		e.opts.WorkflowURLs = sources.RemoteWorkflows
		e.opts.RemoteTemplateDomainList = append(e.opts.RemoteTemplateDomainList, sources.TrustedDomains...)
		return nil
	}
}

// config contains all SDK configuration options
type TemplateFilters struct {
	Severity             string   // filter by severities (accepts CSV values of info, low, medium, high, critical)
	ExcludeSeverities    string   // filter by excluding severities (accepts CSV values of info, low, medium, high, critical)
	ProtocolTypes        string   // filter by protocol types
	ExcludeProtocolTypes string   // filter by excluding protocol types
	Authors              []string // fiter by author
	Tags                 []string // filter by tags present in template
	ExcludeTags          []string // filter by excluding tags present in template
	IncludeTags          []string // filter by including tags present in template
	IDs                  []string // filter by template IDs
	ExcludeIDs           []string // filter by excluding template IDs
	TemplateCondition    []string // DSL condition/ expression
}

// WithTemplateFilters sets template filters and only templates matching the filters will be
// loaded and executed
func WithTemplateFilters(filters TemplateFilters) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		s := severity.Severities{}
		if err := s.Set(filters.Severity); err != nil {
			return err
		}
		es := severity.Severities{}
		if err := es.Set(filters.ExcludeSeverities); err != nil {
			return err
		}
		pt := types.ProtocolTypes{}
		if err := pt.Set(filters.ProtocolTypes); err != nil {
			return err
		}
		ept := types.ProtocolTypes{}
		if err := ept.Set(filters.ExcludeProtocolTypes); err != nil {
			return err
		}
		e.opts.Authors = filters.Authors
		e.opts.Tags = filters.Tags
		e.opts.ExcludeTags = filters.ExcludeTags
		e.opts.IncludeTags = filters.IncludeTags
		e.opts.IncludeIds = filters.IDs
		e.opts.ExcludeIds = filters.ExcludeIDs
		e.opts.Severities = s
		e.opts.ExcludeSeverities = es
		e.opts.Protocols = pt
		e.opts.ExcludeProtocols = ept
		e.opts.IncludeConditions = filters.TemplateCondition
		return nil
	}
}

// InteractshOpts contains options for interactsh
type InteractshOpts interactsh.Options

// WithInteractshOptions sets interactsh options
func WithInteractshOptions(opts InteractshOpts) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithInteractshOptions")
		}
		optsPtr := &opts
		e.interactshOpts = (*interactsh.Options)(optsPtr)
		return nil
	}
}

// Concurrency options
type Concurrency struct {
	TemplateConcurrency           int // number of templates to run concurrently (per host in host-spray mode)
	HostConcurrency               int // number of hosts to scan concurrently  (per template in template-spray mode)
	HeadlessHostConcurrency       int // number of hosts to scan concurrently for headless templates  (per template in template-spray mode)
	HeadlessTemplateConcurrency   int // number of templates to run concurrently for headless templates (per host in host-spray mode)
	JavascriptTemplateConcurrency int // number of templates to run concurrently for javascript templates (per host in host-spray mode)
	TemplatePayloadConcurrency    int // max concurrent payloads to run for a template (a good default is 25)
	ProbeConcurrency              int // max concurrent http probes to run (a good default is 50)
}

// WithConcurrency sets concurrency options
func WithConcurrency(opts Concurrency) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		// minimum required is 1
		if opts.TemplateConcurrency <= 0 {
			return errors.New("template threads must be at least 1")
		}
		if opts.HostConcurrency <= 0 {
			return errors.New("host concurrency must be at least 1")
		}
		if opts.HeadlessHostConcurrency <= 0 {
			return errors.New("headless host concurrency must be at least 1")
		}
		if opts.HeadlessTemplateConcurrency <= 0 {
			return errors.New("headless template threads must be at least 1")
		}
		if opts.JavascriptTemplateConcurrency <= 0 {
			return errors.New("js must be at least 1")
		}
		if opts.TemplatePayloadConcurrency <= 0 {
			return errors.New("payload concurrency must be at least 1")
		}
		if opts.ProbeConcurrency <= 0 {
			return errors.New("probe concurrency must be at least 1")
		}
		e.opts.TemplateThreads = opts.TemplateConcurrency
		e.opts.BulkSize = opts.HostConcurrency
		e.opts.HeadlessBulkSize = opts.HeadlessHostConcurrency
		e.opts.HeadlessTemplateThreads = opts.HeadlessTemplateConcurrency
		e.opts.JsConcurrency = opts.JavascriptTemplateConcurrency
		e.opts.PayloadConcurrency = opts.TemplatePayloadConcurrency
		e.opts.ProbeConcurrency = opts.ProbeConcurrency
		return nil
	}
}

// WithResponseReadSize sets the maximum size of response to read in bytes.
// A value of 0 means no limit. Recommended values: 1MB (1048576) to 10MB (10485760).
func WithResponseReadSize(responseReadSize int) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if responseReadSize < 0 {
			return errors.New("response read size must be non-negative")
		}
		e.opts.ResponseReadSize = responseReadSize
		return nil
	}
}

// WithGlobalRateLimit sets global rate (i.e all hosts combined) limit options
// Deprecated: will be removed in favour of WithGlobalRateLimitCtx in next release
func WithGlobalRateLimit(maxTokens int, duration time.Duration) NucleiSDKOptions {
	return WithGlobalRateLimitCtx(context.Background(), maxTokens, duration)
}

// WithGlobalRateLimitCtx allows setting a global rate limit for the entire engine
func WithGlobalRateLimitCtx(ctx context.Context, maxTokens int, duration time.Duration) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.RateLimit = maxTokens
		e.opts.RateLimitDuration = duration
		e.rateLimiter = ratelimit.New(ctx, uint(e.opts.RateLimit), e.opts.RateLimitDuration)
		return nil
	}
}

// HeadlessOpts contains options for headless templates
type HeadlessOpts struct {
	PageTimeout     int // timeout for page load
	ShowBrowser     bool
	HeadlessOptions []string
	UseChrome       bool
}

// EnableHeadless allows execution of headless templates
// *Use With Caution*: Enabling headless mode may open up attack surface due to browser usage
// and can be prone to exploitation by custom unverified templates if not properly configured
func EnableHeadlessWithOpts(hopts *HeadlessOpts) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.Headless = true
		if hopts != nil {
			e.opts.HeadlessOptionalArguments = hopts.HeadlessOptions
			e.opts.PageTimeout = hopts.PageTimeout
			e.opts.ShowBrowser = hopts.ShowBrowser
			e.opts.UseInstalledChrome = hopts.UseChrome
		}
		if engine.MustDisableSandbox() {
			gologger.Warning().Msgf("The current platform and privileged user will run the browser without sandbox\n")
		}
		browser, err := engine.New(e.opts)
		if err != nil {
			return err
		}
		e.browserInstance = browser
		return nil
	}
}

// StatsOptions
type StatsOptions struct {
	Interval         int
	JSON             bool
	MetricServerPort int
}

// EnableStats enables Stats collection with defined interval(in sec) and callback
// Note: callback is executed in a separate goroutine
func EnableStatsWithOpts(opts StatsOptions) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("EnableStatsWithOpts")
		}
		if opts.Interval == 0 {
			opts.Interval = 5 //sec
		}
		e.opts.StatsInterval = opts.Interval
		e.enableStats = true
		e.opts.StatsJSON = opts.JSON
		e.opts.MetricsPort = opts.MetricServerPort
		return nil
	}
}

// VerbosityOptions
type VerbosityOptions struct {
	Verbose       bool // show verbose output
	Silent        bool // show only results
	Debug         bool // show debug output
	DebugRequest  bool // show request in debug output
	DebugResponse bool // show response in debug output
	ShowVarDump   bool // show variable dumps in output
}

// WithVerbosity allows setting verbosity options of (internal) nuclei engine
// and does not affect SDK output
func WithVerbosity(opts VerbosityOptions) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithVerbosity")
		}
		e.opts.Verbose = opts.Verbose
		e.opts.Silent = opts.Silent
		e.opts.Debug = opts.Debug
		e.opts.DebugRequests = opts.DebugRequest
		e.opts.DebugResponse = opts.DebugResponse
		if opts.ShowVarDump {
			vardump.EnableVarDump = true
		}
		return nil
	}
}

// NetworkConfig contains network config options
// ex: retries , httpx probe , timeout etc
type NetworkConfig struct {
	DisableMaxHostErr     bool     // Disable max host error optimization (Hosts are not skipped even if they are not responding)
	Interface             string   // Interface to use for network scan
	InternalResolversList []string // Use a list of resolver
	LeaveDefaultPorts     bool     // Leave default ports for http/https
	MaxHostError          int      // Maximum number of host errors to allow before skipping that host
	Retries               int      // Number of retries
	SourceIP              string   // SourceIP sets custom source IP address for network requests
	SystemResolvers       bool     // Use system resolvers
	Timeout               int      // Timeout in seconds
	TrackError            []string // Adds given errors to max host error watchlist
}

// WithNetworkConfig allows setting network config options
func WithNetworkConfig(opts NetworkConfig) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithNetworkConfig")
		}
		e.opts.NoHostErrors = opts.DisableMaxHostErr
		e.opts.MaxHostError = opts.MaxHostError
		if e.opts.ShouldUseHostError() {
			maxHostError := opts.MaxHostError
			if e.opts.TemplateThreads > maxHostError {
				gologger.Print().Msgf("[%v] The concurrency value is higher than max-host-error", e.executerOpts.Colorizer.BrightYellow("WRN"))
				gologger.Info().Msgf("Adjusting max-host-error to the concurrency value: %d", e.opts.TemplateThreads)
				maxHostError = e.opts.TemplateThreads
				e.opts.MaxHostError = maxHostError
			}
			cache := hosterrorscache.New(maxHostError, hosterrorscache.DefaultMaxHostsCount, e.opts.TrackError)
			cache.SetVerbose(e.opts.Verbose)
			e.hostErrCache = cache
		}
		e.opts.Timeout = opts.Timeout
		e.opts.Retries = opts.Retries
		e.opts.LeaveDefaultPorts = opts.LeaveDefaultPorts
		e.opts.Interface = opts.Interface
		e.opts.SourceIP = opts.SourceIP
		e.opts.SystemResolvers = opts.SystemResolvers
		e.opts.InternalResolversList = opts.InternalResolversList
		return nil
	}
}

// WithProxy allows setting proxy options
func WithProxy(proxy []string, proxyInternalRequests bool) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithProxy")
		}
		e.opts.Proxy = proxy
		e.opts.ProxyInternal = proxyInternalRequests
		return nil
	}
}

// WithScanStrategy allows setting scan strategy options
func WithScanStrategy(strategy string) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.ScanStrategy = strategy
		return nil
	}
}

// OutputWriter
type OutputWriter output.Writer

// UseOutputWriter allows setting custom output writer
// by default a mock writer is used with user defined callback
// if outputWriter is used callback will be ignored
func UseOutputWriter(writer OutputWriter) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("UseOutputWriter")
		}
		e.customWriter = writer
		return nil
	}
}

// StatsWriter
type StatsWriter progress.Progress

// UseStatsWriter allows setting a custom stats writer
// which can be used to write stats somewhere (ex: send to webserver etc)
func UseStatsWriter(writer StatsWriter) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("UseStatsWriter")
		}
		e.customProgress = writer
		return nil
	}
}

// WithTemplateUpdateCallback allows setting a callback which will be called
// when nuclei templates are outdated
// Note: Nuclei-templates are crucial part of nuclei and using outdated templates or nuclei sdk is not recommended
// as it may cause unexpected results due to compatibility issues
func WithTemplateUpdateCallback(disableTemplatesAutoUpgrade bool, callback func(newVersion string)) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithTemplateUpdateCallback")
		}
		e.disableTemplatesAutoUpgrade = disableTemplatesAutoUpgrade
		e.onUpdateAvailableCallback = callback
		return nil
	}
}

// WithSandboxOptions allows setting supported sandbox options
func WithSandboxOptions(allowLocalFileAccess bool, restrictLocalNetworkAccess bool) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		if e.mode == threadSafe {
			return ErrOptionsNotSupported.Msgf("WithSandboxOptions")
		}
		e.opts.AllowLocalFileAccess = allowLocalFileAccess
		e.opts.RestrictLocalNetworkAccess = restrictLocalNetworkAccess
		return nil
	}
}

// EnableCodeTemplates allows loading/executing code protocol templates
func EnableCodeTemplates() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.EnableCodeTemplates = true
		e.opts.EnableSelfContainedTemplates = true
		return nil
	}
}

// EnableSelfContainedTemplates allows loading/executing self-contained templates
func EnableSelfContainedTemplates() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.EnableSelfContainedTemplates = true
		return nil
	}
}

// EnableGlobalMatchersTemplates allows loading/executing global-matchers templates
func EnableGlobalMatchersTemplates() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.EnableGlobalMatchersTemplates = true
		return nil
	}
}

// EnableFileTemplates allows loading/executing file protocol templates
func EnableFileTemplates() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.EnableFileTemplates = true
		return nil
	}
}

// WithHeaders allows setting custom header/cookie to include in all http request in header:value format
func WithHeaders(headers []string) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.CustomHeaders = headers
		return nil
	}
}

// WithVars allows setting custom variables to use in templates/workflows context
func WithVars(vars []string) NucleiSDKOptions {
	// Create a goflags.RuntimeMap
	runtimeVars := goflags.RuntimeMap{}
	for _, v := range vars {
		err := runtimeVars.Set(v)
		if err != nil {
			return func(e *NucleiEngine) error {
				return err
			}
		}
	}

	return func(e *NucleiEngine) error {
		e.opts.Vars = runtimeVars
		return nil
	}
}

// EnablePassiveMode allows enabling passive HTTP response processing mode
func EnablePassiveMode() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.OfflineHTTP = true
		e.opts.DisableHTTPProbe = true
		return nil
	}
}

// WithAuthProvider allows setting a custom authprovider implementation
func WithAuthProvider(provider authprovider.AuthProvider) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.authprovider = provider
		return nil
	}
}

// LoadSecretsFromFile allows loading secrets from file
func LoadSecretsFromFile(files []string, prefetch bool) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.SecretsFile = goflags.StringSlice(files)
		e.opts.PreFetchSecrets = prefetch
		return nil
	}
}

// DASTMode only run DAST templates
func DASTMode() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.DAST = true
		return nil
	}
}

// SignedTemplatesOnly only run signed templates and disabled loading all unsigned templates
func SignedTemplatesOnly() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.DisableUnsignedTemplates = true
		return nil
	}
}

// WithCatalog uses a supplied catalog
func WithCatalog(cat catalog.Catalog) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.catalog = cat
		return nil
	}
}

// DisableUpdateCheck disables nuclei update check
func DisableUpdateCheck() NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		DefaultConfig.DisableUpdateCheck()
		return nil
	}
}

// WithResumeFile allows setting a resume file
func WithResumeFile(file string) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.Resume = file
		return nil
	}
}
