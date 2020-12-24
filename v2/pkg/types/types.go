package types

import (
	"strings"
)

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// RandomAgent generates random User-Agent
	RandomAgent bool
	// Metrics enables display of metrics via an http endpoint
	Metrics bool
	// Sandbox mode allows users to run isolated workflows with system commands disabled
	Sandbox bool
	// Debug mode allows debugging request/responses for the engine
	Debug bool
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
	// MetricsPort is the port to show metrics on
	MetricsPort int
	// MaxWorkflowDuration is the maximum time a workflow can run for a URL
	MaxWorkflowDuration int
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
	// Thread controls the number of concurrent requests to make.
	Threads int
	// BurpCollaboratorBiid is the Burp Collaborator BIID for polling interactions.
	BurpCollaboratorBiid string
	// ProjectPath allows nuclei to use a user defined project folder
	ProjectPath string
	// Severity filters templates based on their severity and only run the matching ones.
	Severity string
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
	// Templates specifies the template/templates to use
	Templates StringSlice
	// 	ExcludedTemplates  specifies the template/templates to exclude
	ExcludedTemplates StringSlice
	// CustomHeaders is the list of custom global headers to send with each request.
	CustomHeaders StringSlice
}

// StringSlice is a slice of strings as input
type StringSlice []string

// String returns the stringified version of string slice
func (s *StringSlice) String() string {
	return strings.Join(*s, ",")
}

// Set appends a value to the string slice
func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
