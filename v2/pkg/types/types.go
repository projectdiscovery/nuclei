package types

import (
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// Tags contains a list of tags to execute templates for. Multiple paths
	// can be specified with -l flag and -tags can be used in combination with
	// the -l flag.
	Tags goflags.FileNormalizedStringSlice
	// ExcludeTags is the list of tags to exclude
	ExcludeTags goflags.FileNormalizedStringSlice
	// Workflows specifies any workflows to run by nuclei
	Workflows goflags.FileOriginalNormalizedStringSlice
	// WorkflowURLs specifies URLs to a list of workflows to use
	WorkflowURLs goflags.FileOriginalNormalizedStringSlice
	// Templates specifies the template/templates to use
	Templates goflags.FileOriginalNormalizedStringSlice
	// TemplateURLs specifies URLs to a list of templates to use
	TemplateURLs goflags.FileOriginalNormalizedStringSlice
	// RemoteTemplates specifies list of allowed URLs to load remote templates from
	RemoteTemplateDomainList goflags.StringSlice
	// 	ExcludedTemplates  specifies the template/templates to exclude
	ExcludedTemplates goflags.FileOriginalNormalizedStringSlice
	// ExcludeMatchers is a list of matchers to exclude processing
	ExcludeMatchers goflags.FileCommaSeparatedStringSlice
	// CustomHeaders is the list of custom global headers to send with each request.
	CustomHeaders goflags.FileStringSlice
	// Vars is the list of custom global vars
	Vars goflags.RuntimeMap
	// vars to use as iterative payload
	varsPayload map[string]interface{}
	// Severities filters templates based on their severity and only run the matching ones.
	Severities severity.Severities
	// ExcludeSeverities specifies severities to exclude
	ExcludeSeverities severity.Severities
	// Authors filters templates based on their author and only run the matching ones.
	Authors goflags.FileNormalizedStringSlice
	// Protocols contains the protocols to be allowed executed
	Protocols types.ProtocolTypes
	// ExcludeProtocols contains protocols to not be executed
	ExcludeProtocols types.ProtocolTypes
	// IncludeTags includes specified tags to be run even while being in denylist
	IncludeTags goflags.FileNormalizedStringSlice
	// IncludeTemplates includes specified templates to be run even while being in denylist
	IncludeTemplates goflags.FileOriginalNormalizedStringSlice
	// IncludeIds includes specified ids to be run even while being in denylist
	IncludeIds goflags.FileNormalizedStringSlice
	// ExcludeIds contains templates ids to not be executed
	ExcludeIds goflags.FileNormalizedStringSlice

	InternalResolversList []string // normalized from resolvers flag as well as file provided.
	// ProjectPath allows nuclei to use a user defined project folder
	ProjectPath string
	// InteractshURL is the URL for the interactsh server.
	InteractshURL string
	// Interactsh Authorization header value for self-hosted servers
	InteractshToken string
	// Target URLs/Domains to scan using a template
	Targets goflags.StringSlice
	// TargetsFilePath specifies the targets from a file to scan using templates.
	TargetsFilePath string
	// Resume the scan from the state stored in the resume config file
	Resume string
	// Output is the file to write found results to.
	Output string
	// ProxyInternal requests
	ProxyInternal bool
	// List of HTTP(s)/SOCKS5 proxy to use (comma separated or file input)
	Proxy goflags.NormalizedOriginalStringSlice
	// TemplatesDirectory is the directory to use for storing templates
	TemplatesDirectory string
	// TraceLogFile specifies a file to write with the trace of all requests
	TraceLogFile string
	// ErrorLogFile specifies a file to write with the errors of all requests
	ErrorLogFile string
	// ReportingDB is the db for report storage as well as deduplication
	ReportingDB string
	// ReportingConfig is the config file for nuclei reporting module
	ReportingConfig string
	// MarkdownExportDirectory is the directory to export reports in Markdown format
	MarkdownExportDirectory string
	// SarifExport is the file to export sarif output format to
	SarifExport string
	// ResolversFile is a file containing resolvers for nuclei.
	ResolversFile string
	// StatsInterval is the number of seconds to display stats after
	StatsInterval int
	// MetricsPort is the port to show metrics on
	MetricsPort int
	// MaxHostError is the maximum number of errors allowed for a host
	MaxHostError int
	// BulkSize is the of targets analyzed in parallel for each template
	BulkSize int
	// TemplateThreads is the number of templates executed in parallel
	TemplateThreads int
	// HeadlessBulkSize is the of targets analyzed in parallel for each headless template
	HeadlessBulkSize int
	// HeadlessTemplateThreads is the number of headless templates executed in parallel
	HeadlessTemplateThreads int
	// Timeout is the seconds to wait for a response from the server.
	Timeout int
	// Retries is the number of times to retry the request
	Retries int
	// Rate-Limit is the maximum number of requests per specified target
	RateLimit int
	// Rate-Limit is the maximum number of requests per minute for specified target
	RateLimitMinute int
	// PageTimeout is the maximum time to wait for a page in seconds
	PageTimeout int
	// InteractionsCacheSize is the number of interaction-url->req to keep in cache at a time.
	InteractionsCacheSize int
	// InteractionsPollDuration is the number of seconds to wait before each interaction poll
	InteractionsPollDuration int
	// Eviction is the number of seconds after which to automatically discard
	// interaction requests.
	InteractionsEviction int
	// InteractionsCoolDownPeriod is additional seconds to wait for interactions after closing
	// of the poller.
	InteractionsCoolDownPeriod int
	// MaxRedirects is the maximum numbers of redirects to be followed.
	MaxRedirects int
	// FollowRedirects enables following redirects for http request module
	FollowRedirects bool
	// OfflineHTTP is a flag that specific offline processing of http response
	// using same matchers/extractors from http protocol without the need
	// to send a new request, reading responses from a file.
	OfflineHTTP bool
	// StatsJSON writes stats output in JSON format
	StatsJSON bool
	// Headless specifies whether to allow headless mode templates
	Headless bool
	// ShowBrowser specifies whether the show the browser in headless mode
	ShowBrowser bool
	// UseInstalledChrome skips chrome install and use local instance
	UseInstalledChrome bool
	// SystemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool
	// Metrics enables display of metrics via an http endpoint
	Metrics bool
	// Debug mode allows debugging request/responses for the engine
	Debug bool
	// DebugRequests mode allows debugging request for the engine
	DebugRequests bool
	// DebugResponse mode allows debugging response for the engine
	DebugResponse bool
	// LeaveDefaultPorts skips normalization of default ports
	LeaveDefaultPorts bool
	// AutomaticScan enables automatic tech based template execution
	AutomaticScan bool
	// Silent suppresses any extra text and only writes found URLs on screen.
	Silent bool
	// Version specifies if we should just show version and exit
	Version bool
	// Validate validates the templates passed to nuclei.
	Validate bool
	// Verbose flag indicates whether to show verbose output or not
	Verbose        bool
	VerboseVerbose bool
	// No-Color disables the colored output.
	NoColor bool
	// UpdateTemplates updates the templates installed at startup
	UpdateTemplates bool
	// JSON writes json output to files
	JSON bool
	// JSONRequests writes requests/responses for matches in JSON output
	JSONRequests bool
	// EnableProgressBar enables progress bar
	EnableProgressBar bool
	// TemplatesVersion shows the templates installed version
	TemplatesVersion bool
	// TemplateList lists available templates
	TemplateList bool
	// HangMonitor enables nuclei hang monitoring
	HangMonitor bool
	// Stdin specifies whether stdin input was given to the process
	Stdin bool
	// StopAtFirstMatch stops processing template at first full match (this may break chained requests)
	StopAtFirstMatch bool
	// Stream the input without sorting
	Stream bool
	// NoMeta disables display of metadata for the matches
	NoMeta bool
	// NoTimestamp disables display of timestamp for the matcher
	NoTimestamp bool
	// Project is used to avoid sending same HTTP request multiple times
	Project bool
	// NewTemplates only runs newly added templates from the repository
	NewTemplates bool
	// NoInteractsh disables use of interactsh server for interaction polling
	NoInteractsh bool
	// UpdateNuclei checks for an update for the nuclei engine
	UpdateNuclei bool
	// NoUpdateTemplates disables checking for nuclei templates updates
	NoUpdateTemplates bool
	// EnvironmentVariables enables support for environment variables
	EnvironmentVariables bool
	// MatcherStatus displays optional status for the failed matches as well
	MatcherStatus bool
	// ClientCertFile client certificate file (PEM-encoded) used for authenticating against scanned hosts
	ClientCertFile string
	// ClientKeyFile client key file (PEM-encoded) used for authenticating against scanned hosts
	ClientKeyFile string
	// ClientCAFile client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
	ClientCAFile string
	// Use ZTLS library
	ZTLS bool
	// ShowMatchLine enables display of match line number
	ShowMatchLine bool
	// EnablePprof enables exposing pprof runtime information with a webserver.
	EnablePprof bool
	// StoreResponse stores received response to output directory
	StoreResponse bool
	// StoreResponseDir stores received response to custom directory
	StoreResponseDir string
	// DisableRedirects disables following redirects for http request module
	DisableRedirects bool
	// SNI custom hostname
	SNI string
}

func (options *Options) AddVarPayload(key string, value interface{}) {
	if options.varsPayload == nil {
		options.varsPayload = make(map[string]interface{})
	}

	options.varsPayload[key] = value
}

func (options *Options) VarsPayload() map[string]interface{} {
	return options.varsPayload
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume != "" && fileutil.FileExists(options.Resume)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// DefaultOptions returns default options for nuclei
func DefaultOptions() *Options {
	return &Options{
		RateLimit:               150,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		HeadlessTemplateThreads: 10,
		Timeout:                 5,
		Retries:                 1,
		MaxHostError:            30,
	}
}
