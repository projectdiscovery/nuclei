package types

import "github.com/projectdiscovery/goflags"

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// Tags contains a list of tags to execute templates for. Multiple paths
	// can be specified with -l flag and -tags can be used in combination with
	// the -l flag.
	Tags goflags.StringSlice
	// Templates specifies the template/templates to use
	Templates goflags.StringSlice
	// 	ExcludedTemplates  specifies the template/templates to exclude
	ExcludedTemplates goflags.StringSlice
	// CustomHeaders is the list of custom global headers to send with each request.
	CustomHeaders goflags.StringSlice
	// Severity filters templates based on their severity and only run the matching ones.
	Severity              goflags.StringSlice
	InternalResolversList []string // normalized from resolvers flag as well as file provided.
	// BurpCollaboratorBiid is the Burp Collaborator BIID for polling interactions.
	BurpCollaboratorBiid string
	// ProjectPath allows nuclei to use a user defined project folder
	ProjectPath string
	// Target is a single URL/Domain to scan using a template
	Target string
	// Targets specifies the targets to scan using templates.
	Targets string
	// Output is the file to write found results to.
	Output string
	// ProxyURL is the URL for the proxy server
	ProxyURL string
	// ProxySocksURL is the URL for the proxy socks server
	ProxySocksURL string
	// TemplatesDirectory is the directory to use for storing templates
	TemplatesDirectory string
	// TraceLogFile specifies a file to write with the trace of all requests
	TraceLogFile string
	// ReportingDB is the db for report storage as well as deduplication
	ReportingDB string
	// ReportingConfig is the config file for nuclei reporting module
	ReportingConfig string
	// ResolversFile is a file containing resolvers for nuclei.
	ResolversFile string
	// StatsInterval is the number of seconds to display stats after
	StatsInterval int
	// MetricsPort is the port to show metrics on
	MetricsPort int
	// BulkSize is the of targets analyzed in parallel for each template
	BulkSize int
	// TemplateThreads is the number of templates executed in parallel
	TemplateThreads int
	// Timeout is the seconds to wait for a response from the server.
	Timeout int
	// Retries is the number of times to retry the request
	Retries int
	// Rate-Limit is the maximum number of requests per specified target
	RateLimit int
	//`PageTimeout is the maximum time to wait for a page in seconds
	PageTimeout int
	// OfflineHTTP is a flag that specific offline processing of http response
	// using same matchers/extractors from http protocol without the need
	// to send a new request, reading responses from a file.
	OfflineHTTP bool
	// Headless specifies whether to allow headless mode templates
	Headless bool
	// ShowBrowser specifies whether the show the browser in headless mode
	ShowBrowser bool
	// Workflows specifies if only to execute workflows (no normal templates will be run)
	Workflows bool
	// SytemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool
	// RandomAgent generates random User-Agent
	RandomAgent bool
	// Metrics enables display of metrics via an http endpoint
	Metrics bool
	// Debug mode allows debugging request/responses for the engine
	Debug bool
	// DebugRequests mode allows debugging request for the engine
	DebugRequests bool
	// DebugResponse mode allows debugging response for the engine
	DebugResponse bool
	// Silent suppresses any extra text and only writes found URLs on screen.
	Silent bool
	// Version specifies if we should just show version and exit
	Version bool
	// Verbose flag indicates whether to show verbose output or not
	Verbose bool
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
	// Stdin specifies whether stdin input was given to the process
	Stdin bool
	// StopAtFirstMatch stops processing template at first full match (this may break chained requests)
	StopAtFirstMatch bool
	// NoMeta disables display of metadata for the matches
	NoMeta bool
	// Project is used to avoid sending same HTTP request multiple times
	Project bool
}
