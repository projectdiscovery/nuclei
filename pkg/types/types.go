package types

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	unitutils "github.com/projectdiscovery/utils/unit"
)

var (
	// ErrNoMoreRequests is internal error to indicate that generator has no more requests to generate
	ErrNoMoreRequests = io.EOF
)

// LoadHelperFileFunction can be used to load a helper file.
type LoadHelperFileFunction func(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error)

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
	// AITemplatePrompt specifies prompt to generate template using AI
	AITemplatePrompt string
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
	// InternalResolversList is the list of internal resolvers to use
	InternalResolversList []string
	// ProjectPath allows nuclei to use a user defined project folder
	ProjectPath string
	// InteractshURL is the URL for the interactsh server.
	InteractshURL string
	// Interactsh Authorization header value for self-hosted servers
	InteractshToken string
	// Target URLs/Domains to scan using a template
	Targets goflags.StringSlice
	// ExcludeTargets URLs/Domains to exclude from scanning
	ExcludeTargets goflags.StringSlice
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
	// AliveProxy is the alive proxy to use
	AliveHttpProxy string
	// AliveSocksProxy is the alive socks proxy to use
	AliveSocksProxy string
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
	// Rate Limit Duration interval between burst resets
	RateLimitDuration time.Duration
	// Rate-Limit is the maximum number of requests per minute for specified target
	// Deprecated: Use RateLimitDuration - automatically set Rate Limit Duration to 60 seconds
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
	// DisableClustering disables clustering of templates
	DisableClustering bool
	// UseInstalledChrome skips chrome install and use local instance
	UseInstalledChrome bool
	// SystemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool
	// ShowActions displays a list of all headless actions
	ShowActions bool
	// Deprecated: Enabled by default through clistats . Metrics enables display of metrics via an http endpoint
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
	// VarDumpLimit limits the number of characters displayed in var dump
	VarDumpLimit int
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
	// HTTPStats enables http statistics tracking and display.
	HTTPStats bool
	// OmitTemplate omits encoded template from JSON output
	OmitTemplate bool
	// JSONExport is the file to export JSON output format to
	JSONExport string
	// JSONLExport is the file to export JSONL output format to
	JSONLExport string
	// Redact redacts given keys in
	Redact goflags.StringSlice
	// EnableProgressBar enables progress bar
	EnableProgressBar bool
	// TemplateDisplay displays the template contents
	TemplateDisplay bool
	// TemplateList lists available templates
	TemplateList bool
	// TemplateList lists available tags
	TagList bool
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
	// InputFileMode specifies the mode of input file (jsonl, burp, openapi, swagger, etc)
	InputFileMode string
	// DialerKeepAlive sets the keep alive duration for network requests.
	DialerKeepAlive time.Duration
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
	// DisplayFuzzPoints enables display of fuzz points for fuzzing
	DisplayFuzzPoints bool
	// FuzzAggressionLevel is the level of fuzzing aggression (low, medium, high.)
	FuzzAggressionLevel string
	// FuzzParamFrequency is the frequency of fuzzing parameters
	FuzzParamFrequency int
	// CodeTemplateSignaturePublicKey is the custom public key used to verify the template signature (algorithm is automatically inferred from the length)
	CodeTemplateSignaturePublicKey string
	// CodeTemplateSignatureAlgorithm specifies the sign algorithm (rsa, ecdsa)
	CodeTemplateSignatureAlgorithm string
	// SignTemplates enables signing of templates
	SignTemplates bool
	// EnableCodeTemplates enables code templates
	EnableCodeTemplates bool
	// DisableUnsignedTemplates disables processing of unsigned templates
	DisableUnsignedTemplates bool
	// EnableSelfContainedTemplates enables processing of self-contained templates
	EnableSelfContainedTemplates bool
	// EnableGlobalMatchersTemplates enables processing of global-matchers templates
	EnableGlobalMatchersTemplates bool
	// EnableFileTemplates enables file templates
	EnableFileTemplates bool
	// Disables cloud upload
	EnableCloudUpload bool
	// ScanID is the scan ID to use for cloud upload
	ScanID string
	// ScanName is the name of the scan to be uploaded
	ScanName string
	// ScanUploadFile is the jsonl file to upload scan results to cloud
	ScanUploadFile string
	// TeamID is the team ID to use for cloud upload
	TeamID string
	// JsConcurrency is the number of concurrent js routines to run
	JsConcurrency int
	// SecretsFile is file containing secrets for nuclei
	SecretsFile goflags.StringSlice
	// PreFetchSecrets pre-fetches the secrets from the auth provider
	PreFetchSecrets bool
	// FormatUseRequiredOnly only uses required fields when generating requests
	FormatUseRequiredOnly bool
	// SkipFormatValidation is used to skip format validation
	SkipFormatValidation bool
	// PayloadConcurrency is the number of concurrent payloads to run per template
	PayloadConcurrency int
	// ProbeConcurrency is the number of concurrent http probes to run with httpx
	ProbeConcurrency int
	// Dast only runs DAST templates
	DAST bool
	// DASTServer is the flag to start nuclei as a DAST server
	DASTServer bool
	// DASTServerToken is the token optional for the dast server
	DASTServerToken string
	// DASTServerAddress is the address for the dast server
	DASTServerAddress string
	// DASTReport enables dast report server & final report generation
	DASTReport bool
	// Scope contains a list of regexes for in-scope URLS
	Scope goflags.StringSlice
	// OutOfScope contains a list of regexes for out-scope URLS
	OutOfScope goflags.StringSlice
	// HttpApiEndpoint is the experimental http api endpoint
	HttpApiEndpoint string
	// ListTemplateProfiles lists all available template profiles
	ListTemplateProfiles bool
	// LoadHelperFileFunction is a function that will be used to execute LoadHelperFile.
	// If none is provided, then the default implementation will be used.
	LoadHelperFileFunction LoadHelperFileFunction
	// timeouts contains various types of timeouts used in nuclei
	// these timeouts are derived from dial-timeout (-timeout) with known multipliers
	// This is internally managed and does not need to be set by user by explicitly setting
	// this overrides the default/derived one
	timeouts *Timeouts
}

// SetTimeouts sets the timeout variants to use for the executor
func (opts *Options) SetTimeouts(t *Timeouts) {
	opts.timeouts = t
}

// GetTimeouts returns the timeout variants to use for the executor
func (eo *Options) GetTimeouts() *Timeouts {
	if eo.timeouts != nil {
		// redundant but apply to avoid any potential issues
		eo.timeouts.ApplyDefaults()
		return eo.timeouts
	}
	// set timeout variant value
	eo.timeouts = NewTimeoutVariant(eo.Timeout)
	eo.timeouts.ApplyDefaults()
	return eo.timeouts
}

// Timeouts is a struct that contains all the timeout variants for nuclei
// dialer timeout is used to derive other timeouts
type Timeouts struct {
	// DialTimeout for fastdialer (default 10s)
	DialTimeout time.Duration
	// Tcp(Network Protocol) Read From Connection Timeout (default 5s)
	TcpReadTimeout time.Duration
	// Http Response Header Timeout (default 10s)
	// this timeout prevents infinite hangs started by server if any
	// this is temporarily overridden when using @timeout request annotation
	HttpResponseHeaderTimeout time.Duration
	// HttpTimeout for http client (default -> 3 x dial-timeout = 30s)
	HttpTimeout time.Duration
	// JsCompilerExec timeout/deadline (default -> 2 x dial-timeout = 20s)
	JsCompilerExecutionTimeout time.Duration
	// CodeExecutionTimeout for code execution (default -> 3 x dial-timeout = 30s)
	CodeExecutionTimeout time.Duration
}

// NewTimeoutVariant creates a new timeout variant with the given dial timeout in seconds
func NewTimeoutVariant(dialTimeoutSec int) *Timeouts {
	tv := &Timeouts{
		DialTimeout: time.Duration(dialTimeoutSec) * time.Second,
	}
	tv.ApplyDefaults()
	return tv
}

// ApplyDefaults applies default values to timeout variants when missing
func (tv *Timeouts) ApplyDefaults() {
	if tv.DialTimeout == 0 {
		tv.DialTimeout = 10 * time.Second
	}
	if tv.TcpReadTimeout == 0 {
		tv.TcpReadTimeout = 5 * time.Second
	}
	if tv.HttpResponseHeaderTimeout == 0 {
		tv.HttpResponseHeaderTimeout = 10 * time.Second
	}
	if tv.HttpTimeout == 0 {
		tv.HttpTimeout = 3 * tv.DialTimeout
	}
	if tv.JsCompilerExecutionTimeout == 0 {
		tv.JsCompilerExecutionTimeout = 2 * tv.DialTimeout
	}
	if tv.CodeExecutionTimeout == 0 {
		tv.CodeExecutionTimeout = 3 * tv.DialTimeout
	}
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
		RateLimitDuration:       time.Second,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		PayloadConcurrency:      25,
		HeadlessTemplateThreads: 10,
		ProbeConcurrency:        50,
		Timeout:                 5,
		Retries:                 1,
		MaxHostError:            30,
		ResponseReadSize:        10 * unitutils.Mega,
		ResponseSaveSize:        unitutils.Mega,
	}
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

// LoadHelperFile loads a helper file needed for the template.
//
// If LoadHelperFileFunction is set, then that function will be used.
// Otherwise, the default implementation will be used, which respects the sandbox rules and only loads files from allowed directories.
func (options *Options) LoadHelperFile(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error) {
	if options.LoadHelperFileFunction != nil {
		return options.LoadHelperFileFunction(helperFile, templatePath, catalog)
	}
	return options.defaultLoadHelperFile(helperFile, templatePath, catalog)
}

// defaultLoadHelperFile loads a helper file needed for the template
// this respects the sandbox rules and only loads files from
// allowed directories
func (options *Options) defaultLoadHelperFile(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error) {
	if !options.AllowLocalFileAccess {
		// if global file access is disabled try loading with restrictions
		absPath, err := options.GetValidAbsPath(helperFile, templatePath)
		if err != nil {
			return nil, err
		}
		helperFile = absPath
	}
	f, err := os.Open(helperFile)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not open file %v", helperFile)
	}
	return f, nil
}

// GetValidAbsPath returns absolute path of helper file if it is allowed to be loaded
// this respects the sandbox rules and only loads files from allowed directories
func (o *Options) GetValidAbsPath(helperFilePath, templatePath string) (string, error) {
	// Conditions to allow helper file
	// 1. If helper file is present in nuclei-templates directory
	// 2. If helper file and template file are in same directory given that its not root directory

	// resolve and clean helper file path
	// ResolveNClean uses a custom base path instead of CWD
	resolvedPath, err := fileutil.ResolveNClean(helperFilePath, config.DefaultConfig.GetTemplateDir())
	if err == nil {
		// As per rule 1, if helper file is present in nuclei-templates directory, allow it
		if strings.HasPrefix(resolvedPath, config.DefaultConfig.GetTemplateDir()) {
			return resolvedPath, nil
		}
	}

	// CleanPath resolves using CWD and cleans the path
	helperFilePath, err = fileutil.CleanPath(helperFilePath)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not clean helper file path %v", helperFilePath)
	}

	templatePath, err = fileutil.CleanPath(templatePath)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not clean template path %v", templatePath)
	}

	// As per rule 2, if template and helper file exist in same directory or helper file existed in any child dir of template dir
	// and both of them are present in user home directory, allow it
	// Review: should we keep this rule ? add extra option to disable this ?
	if isHomeDir(helperFilePath) && isHomeDir(templatePath) && strings.HasPrefix(filepath.Dir(helperFilePath), filepath.Dir(templatePath)) {
		return helperFilePath, nil
	}

	// all other cases are denied
	return "", errorutil.New("access to helper file %v denied", helperFilePath)
}

// isHomeDir checks if given is home directory
func isHomeDir(path string) bool {
	homeDir := folderutil.HomeDirOrDefault("")
	return strings.HasPrefix(path, homeDir)
}
