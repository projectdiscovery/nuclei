package types

import (
	"io"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	// ErrNoMoreRequests is internal error to indicate that generator has no more requests to generate
	ErrNoMoreRequests = io.EOF
)

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// Tags contains a list of tags to execute templates for. Multiple paths
	// can be specified with -l flag and -tags can be used in combination with
	// the -l flag.
	Tags goflags.StringSlice
	// ExcludeTags is the list of tags to exclude
	ExcludeTags goflags.StringSlice
	// Workflows specifies any workflows to run by nuclei
	Workflows goflags.StringSlice
	// WorkflowURLs specifies URLs to a list of workflows to use
	WorkflowURLs goflags.StringSlice
	// Templates specifies the template/templates to use
	Templates goflags.StringSlice
	// TemplateURLs specifies URLs to a list of templates to use
	TemplateURLs goflags.StringSlice
	// RemoteTemplates specifies list of allowed URLs to load remote templates from
	RemoteTemplateDomainList goflags.StringSlice
	// 	ExcludedTemplates  specifies the template/templates to exclude
	ExcludedTemplates goflags.StringSlice
	// ExcludeMatchers is a list of matchers to exclude processing
	ExcludeMatchers goflags.StringSlice
	// CustomHeaders is the list of custom global headers to send with each request.
	CustomHeaders goflags.StringSlice
	// Vars is the list of custom global vars
	Vars goflags.RuntimeMap
	// Severities filters templates based on their severity and only run the matching ones.
	Severities severity.Severities
	// ExcludeSeverities specifies severities to exclude
	ExcludeSeverities severity.Severities
	// Authors filters templates based on their author and only run the matching ones.
	Authors goflags.StringSlice
	// Protocols contains the protocols to be allowed executed
	Protocols types.ProtocolTypes
	// ExcludeProtocols contains protocols to not be executed
	ExcludeProtocols types.ProtocolTypes
	// IncludeTags includes specified tags to be run even while being in denylist
	IncludeTags goflags.StringSlice
	// IncludeTemplates includes specified templates to be run even while being in denylist
	IncludeTemplates goflags.StringSlice
	// IncludeIds includes specified ids to be run even while being in denylist
	IncludeIds goflags.StringSlice
	// ExcludeIds contains templates ids to not be executed
	ExcludeIds goflags.StringSlice

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
	// Show all supported DSL signatures
	ListDslSignatures bool
	// List of HTTP(s)/SOCKS5 proxy to use (comma separated or file input)
	Proxy goflags.StringSlice
	// TemplatesDirectory is the directory to use for storing templates
	NewTemplatesDirectory string
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
	// MarkdownExportSortMode is the method to sort the markdown reports (options: severity, template, host, none)
	MarkdownExportSortMode string
	// SarifExport is the file to export sarif output format to
	SarifExport string
	// CloudURL is the URL for the nuclei cloud endpoint
	CloudURL string
	// CloudAPIKey is the api-key for the nuclei cloud endpoint
	CloudAPIKey string
	// ScanList feature to get all the scan ids for a user
	ScanList bool
	// ListDatasources enables listing of datasources for user
	ListDatasources bool
	// ListTargets enables listing of targets for user
	ListTargets bool
	// ListTemplates enables listing of templates for user
	ListTemplates bool
	// ListReportingSources enables listing of reporting source
	ListReportingSources bool
	// DisableReportingSource disables a reporting source
	DisableReportingSource string
	// EnableReportingSource enables a reporting source
	EnableReportingSource string
	// Limit the number of items at a time
	OutputLimit int
	// Nostore
	NoStore bool
	// Delete scan
	DeleteScan string
	// AddDatasource adds a datasource to cloud storage
	AddDatasource string
	// RemoveDatasource deletes a datasource from cloud storage
	RemoveDatasource string
	// AddTemplate adds a list of templates to custom datasource
	AddTemplate string
	// AddTarget adds a list of targets to custom datasource
	AddTarget string
	// GetTemplate gets a template by id
	GetTemplate string
	// GetTarget gets a target by id
	GetTarget string
	// RemoveTemplate removes a list of templates
	RemoveTemplate string
	// RemoveTarget removes a list of targets
	RemoveTarget string
	// Get issues for a scan
	ScanOutput string
	// ResolversFile is a file containing resolvers for nuclei.
	ResolversFile string
	// StatsInterval is the number of seconds to display stats after
	StatsInterval int
	// MetricsPort is the port to show metrics on
	MetricsPort int
	// MaxHostError is the maximum number of errors allowed for a host
	MaxHostError int
	// TrackError contains additional error messages that count towards the maximum number of errors allowed for a host
	TrackError goflags.StringSlice
	// NoHostErrors disables host skipping after maximum number of errors
	NoHostErrors bool
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
	// FollowRedirects enables following redirects for http request module only on the same host
	FollowHostRedirects bool
	// OfflineHTTP is a flag that specific offline processing of http response
	// using same matchers/extractors from http protocol without the need
	// to send a new request, reading responses from a file.
	OfflineHTTP bool
	// Force HTTP2 requests
	ForceAttemptHTTP2 bool
	// StatsJSON writes stats output in JSON format
	StatsJSON bool
	// Headless specifies whether to allow headless mode templates
	Headless bool
	// ShowBrowser specifies whether the show the browser in headless mode
	ShowBrowser bool
	// HeadlessOptionalArguments specifies optional arguments to pass to Chrome
	HeadlessOptionalArguments goflags.StringSlice
	// NoTables disables pretty printing of cloud results in tables
	NoTables bool
	// DisableClustering disables clustering of templates
	DisableClustering bool
	// UseInstalledChrome skips chrome install and use local instance
	UseInstalledChrome bool
	// SystemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool
	// ShowActions displays a list of all headless actions
	ShowActions bool
	// Metrics enables display of metrics via an http endpoint
	Metrics bool
	// Debug mode allows debugging request/responses for the engine
	Debug bool
	// DebugRequests mode allows debugging request for the engine
	DebugRequests bool
	// DebugResponse mode allows debugging response for the engine
	DebugResponse bool
	// DisableHTTPProbe disables http probing feature of input normalization
	DisableHTTPProbe bool
	// LeaveDefaultPorts skips normalization of default ports
	LeaveDefaultPorts bool
	// AutomaticScan enables automatic tech based template execution
	AutomaticScan bool
	// Silent suppresses any extra text and only writes found URLs on screen.
	Silent bool
	// Validate validates the templates passed to nuclei.
	Validate bool
	// NoStrictSyntax disables strict syntax check on nuclei templates (allows custom key-value pairs).
	NoStrictSyntax bool
	// Verbose flag indicates whether to show verbose output or not
	Verbose        bool
	VerboseVerbose bool
	// ShowVarDump displays variable dump
	ShowVarDump bool
	// No-Color disables the colored output.
	NoColor bool
	// UpdateTemplates updates the templates installed at startup (also used by cloud to update datasources)
	UpdateTemplates bool
	// JSON writes json line output to files
	JSONL bool
	// JSONRequests writes requests/responses for matches in JSON output
	// Deprecated: use OmitRawRequests instead as of now JSONRequests(include raw requests) is always true
	JSONRequests bool
	// OmitRawRequests omits requests/responses for matches in JSON output
	OmitRawRequests bool
	// JSONExport is the file to export JSON output format to
	JSONExport string
	// JSONLExport is the file to export JSONL output format to
	JSONLExport string
	// Cloud enables nuclei cloud scan execution
	Cloud bool
	// EnableProgressBar enables progress bar
	EnableProgressBar bool
	// TemplateDisplay displays the template contents
	TemplateDisplay bool
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
	// Timestamp enables display of timestamp for the matcher
	Timestamp bool
	// Project is used to avoid sending same HTTP request multiple times
	Project bool
	// NewTemplates only runs newly added templates from the repository
	NewTemplates bool
	// NewTemplatesWithVersion runs new templates added in specific version
	NewTemplatesWithVersion goflags.StringSlice
	// NoInteractsh disables use of interactsh server for interaction polling
	NoInteractsh bool
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
	// Deprecated: Use ZTLS library
	ZTLS bool
	// AllowLocalFileAccess allows local file access from templates payloads
	AllowLocalFileAccess bool
	// RestrictLocalNetworkAccess restricts local network access from templates requests
	RestrictLocalNetworkAccess bool
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
	// Interface to use for network scan
	Interface string
	// SourceIP sets custom source IP address for network requests
	SourceIP string
	// AttackType overrides template level attack-type configuration
	AttackType string
	// ResponseReadSize is the maximum size of response to read
	ResponseReadSize int
	// ResponseSaveSize is the maximum size of response to save
	ResponseSaveSize int
	// Health Check
	HealthCheck bool
	// Time to wait between each input read operation before closing the stream
	InputReadTimeout time.Duration
	// Disable stdin for input processing
	DisableStdin bool
	// IncludeConditions is the list of conditions templates should match
	IncludeConditions goflags.StringSlice
	// Custom Config Directory
	CustomConfigDir string
	// Enable uncover engine
	Uncover bool
	// Uncover search query
	UncoverQuery goflags.StringSlice
	// Uncover search engine
	UncoverEngine goflags.StringSlice
	// Uncover search field
	UncoverField string
	// Uncover search limit
	UncoverLimit int
	// Uncover search delay
	UncoverRateLimit int
	// ScanAllIPs associated to a dns record
	ScanAllIPs bool
	// IPVersion to scan (4,6)
	IPVersion goflags.StringSlice
	// PublicTemplateDisableDownload disables downloading templates from the nuclei-templates public repository
	PublicTemplateDisableDownload bool
	// GitHub token used to clone/pull from private repos for custom templates
	GitHubToken string
	// GitHubTemplateRepo is the list of custom public/private templates GitHub repos
	GitHubTemplateRepo []string
	// GitHubTemplateDisableDownload disables downloading templates from custom GitHub repositories
	GitHubTemplateDisableDownload bool
	// GitLabServerURL is the gitlab server to use for custom templates
	GitLabServerURL string
	// GitLabToken used to clone/pull from private repos for custom templates
	GitLabToken string
	// GitLabTemplateRepositoryIDs is the comma-separated list of custom gitlab repositories IDs
	GitLabTemplateRepositoryIDs []int
	// GitLabTemplateDisableDownload disables downloading templates from custom GitLab repositories
	GitLabTemplateDisableDownload bool
	// AWS access key for downloading templates from S3 bucket
	AwsAccessKey string
	// AWS secret key for downloading templates from S3 bucket
	AwsSecretKey string
	// AWS bucket name for downloading templates from S3 bucket
	AwsBucketName string
	// AWS Region name where AWS S3 bucket is located
	AwsRegion string
	// AwsTemplateDisableDownload disables downloading templates from AWS S3 buckets
	AwsTemplateDisableDownload bool
	// AzureContainerName for downloading templates from Azure Blob Storage. Example: templates
	AzureContainerName string
	// AzureTenantID for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureTenantID string
	// AzureClientID for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureClientID string
	// AzureClientSecret for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureClientSecret string
	// AzureServiceURL for downloading templates from Azure Blob Storage. Example: https://XXXXXXXXXX.blob.core.windows.net/
	AzureServiceURL string
	// AzureTemplateDisableDownload disables downloading templates from Azure Blob Storage
	AzureTemplateDisableDownload bool
	// Scan Strategy (auto,hosts-spray,templates-spray)
	ScanStrategy string
	// Fuzzing Type overrides template level fuzzing-type configuration
	FuzzingType string
	// Fuzzing Mode overrides template level fuzzing-mode configuration
	FuzzingMode string
	// TlsImpersonate enables TLS impersonation
	TlsImpersonate bool
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume != "" && fileutil.FileExists(options.Resume)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// ShouldFollowHTTPRedirects determines if http redirects should be followed
func (options *Options) ShouldFollowHTTPRedirects() bool {
	return options.FollowRedirects || options.FollowHostRedirects
}

// HasClientCertificates determines if any client certificate was specified
func (options *Options) HasClientCertificates() bool {
	return options.ClientCertFile != "" || options.ClientCAFile != "" || options.ClientKeyFile != ""
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
		ResponseReadSize:        10 * 1024 * 1024,
		ResponseSaveSize:        1024 * 1024,
	}
}

// HasCloudOptions returns true if cloud options have been specified
func (options *Options) HasCloudOptions() bool {
	return options.ScanList ||
		options.DeleteScan != "" ||
		options.ScanOutput != "" ||
		options.ListDatasources ||
		options.ListTargets ||
		options.ListTemplates ||
		options.RemoveDatasource != "" ||
		options.AddTarget != "" ||
		options.AddTemplate != "" ||
		options.RemoveTarget != "" ||
		options.RemoveTemplate != "" ||
		options.GetTarget != "" ||
		options.GetTemplate != ""
}

func (options *Options) ShouldUseHostError() bool {
	return options.MaxHostError > 0 && !options.NoHostErrors
}

func (options *Options) ParseHeadlessOptionalArguments() map[string]string {
	optionalArguments := make(map[string]string)
	for _, v := range options.HeadlessOptionalArguments {
		if argParts := strings.SplitN(v, "=", 2); len(argParts) >= 2 {
			key := strings.TrimSpace(argParts[0])
			value := strings.TrimSpace(argParts[1])
			if key != "" && value != "" {
				optionalArguments[key] = value
			}
		}
	}
	return optionalArguments
}
