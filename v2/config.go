package nuclei

import (
	"context"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/ratelimit"
)

// config contains all SDK configuration options
type TemplateFilters struct {
	Severity             string   // filter by severities (accepts CSV values of info, low, medium, high, critical)
	ExcludeSeverities    string   // filter by excluding severities (accepts CSV values of info, low, medium, high, critical)
	Authors              []string // fiter by author
	Tags                 []string // filter by tags present in template
	ExcludeTags          []string // filter by excluding tags present in template
	IncludeTags          []string // filter by including tags present in template
	IDs                  []string // filter by template IDs
	ExcludeIDs           []string // filter by excluding template IDs
	ProtocolTypes        []string // filter by protocol types
	ExcludeProtocolTypes []string // filter by excluding protocol types
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
		e.opts.Authors = filters.Authors
		e.opts.Tags = filters.Tags
		e.opts.ExcludeTags = filters.ExcludeTags
		e.opts.IncludeTags = filters.IncludeTags
		e.opts.IncludeIds = filters.IDs
		e.opts.ExcludeIds = filters.ExcludeIDs
		e.opts.Severities = s
		e.opts.ExcludeSeverities = es
		e.opts.IncludeConditions = filters.TemplateCondition
		return nil
	}
}

// InteractshOpts contains options for interactsh
type InteractshOpts interactsh.Options

// WithInteractshOptions sets interactsh options
func WithInteractshOptions(opts InteractshOpts) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		optsPtr := &opts
		e.interactshOpts = (*interactsh.Options)(optsPtr)
		return nil
	}
}

// Concurrency options
type Concurrency struct {
	TemplateConcurrency         int // number of templates to run concurrently (per host in host-spray mode)
	HostConcurrency             int // number of hosts to scan concurrently  (per template in template-spray mode)
	HeadlessHostConcurrency     int // number of hosts to scan concurrently for headless templates  (per template in template-spray mode)
	HeadlessTemplateConcurrency int // number of templates to run concurrently for headless templates (per host in host-spray mode)
}

// WithConcurrency sets concurrency options
func WithConcurrency(opts Concurrency) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.TemplateThreads = opts.TemplateConcurrency
		e.opts.BulkSize = opts.HostConcurrency
		e.opts.HeadlessBulkSize = opts.HeadlessHostConcurrency
		e.opts.HeadlessTemplateThreads = opts.HeadlessTemplateConcurrency
		return nil
	}
}

// WithGlobalRateLimit sets global rate (i.e all hosts combined) limit options
func WithGlobalRateLimit(maxTokens int, duration time.Duration) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.rateLimiter = ratelimit.New(context.Background(), uint(maxTokens), duration)
		return nil
	}
}

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
		return nil
	}
}

// EnableStats enables Stats collection with defined interval(in sec) and callback
// Note: callback is executed in a separate goroutine
func EnableStatsWithOpts(interval int, callback func()) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.StatsInterval = interval
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
		e.opts.Verbose = opts.Verbose
		e.opts.Silent = opts.Silent
		e.opts.Debug = opts.Debug
		e.opts.DebugRequests = opts.DebugRequest
		e.opts.DebugResponse = opts.DebugResponse
		e.opts.ShowVarDump = opts.ShowVarDump
		return nil
	}
}

// NetworkConfig contains network config options
// ex: retries , httpx probe , timeout etc
type NetworkConfig struct {
	Timeout           int      // Timeout in seconds
	Retries           int      // Number of retries
	LeaveDefaultPorts bool     // Leave default ports for http/https
	MaxHostError      int      // Maximum number of host errors to allow before skipping that host
	TrackError        []string // Adds given errors to max host error watchlist
	DisableMaxHostErr bool     // Disable max host error optimization (Hosts are not skipped even if they are not responding)
}

// WithNetworkConfig allows setting network config options
func WithNetworkConfig(opts NetworkConfig) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.Timeout = opts.Timeout
		e.opts.Retries = opts.Retries
		e.opts.LeaveDefaultPorts = opts.LeaveDefaultPorts
		e.hostErrCache = hosterrorscache.New(opts.MaxHostError, hosterrorscache.DefaultMaxHostsCount, opts.TrackError)
		return nil
	}
}

// WithProxy allows setting proxy options
func WithProxy(proxy []string, proxyInternalRequests bool) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
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

// UseWriter allows setting custom output writer
// by default a mock writer is used with user defined callback
// if outputWriter is used callback will be ignored
func UseOutputWriter(writer OutputWriter) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
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
		e.customProgress = writer
		return nil
	}
}
