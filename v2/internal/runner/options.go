package runner

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// Vhost marks the input specified as VHOST input
	Vhost bool
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
	CustomHeaders requests.CustomHeaders
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

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flag.BoolVar(&options.Vhost, "vhost", false, "Input supplied is a comma-separated vhost list")
	flag.BoolVar(&options.Sandbox, "sandbox", false, "Run workflows in isolated sandbox mode")
	flag.BoolVar(&options.Metrics, "metrics", false, "Expose nuclei metrics on a port")
	flag.IntVar(&options.MetricsPort, "metrics-port", 9092, "Port to expose nuclei metrics on")
	flag.IntVar(&options.MaxWorkflowDuration, "workflow-duration", 10, "Max time for workflow run on single URL in minutes")
	flag.StringVar(&options.Target, "target", "", "Target is a single target to scan using template")
	flag.Var(&options.Templates, "t", "Template input dir/file/files to run on host. Can be used multiple times. Supports globbing.")
	flag.Var(&options.ExcludedTemplates, "exclude", "Template input dir/file/files to exclude. Can be used multiple times. Supports globbing.")
	flag.StringVar(&options.Severity, "severity", "", "Filter templates based on their severity and only run the matching ones. Comma-separated values can be used to specify multiple severities.")
	flag.StringVar(&options.Targets, "l", "", "List of URLs to run templates on")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.StringVar(&options.ProxyURL, "proxy-url", "", "URL of the proxy server")
	flag.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the proxy socks server")
	flag.BoolVar(&options.Silent, "silent", false, "Show only results in output")
	flag.BoolVar(&options.Version, "version", false, "Show version of nuclei")
	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "no-color", false, "Disable colors in output")
	flag.IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout")
	flag.IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request")
	flag.BoolVar(&options.RandomAgent, "random-agent", false, "Use randomly selected HTTP User-Agent header value")
	flag.Var(&options.CustomHeaders, "H", "Custom Header.")
	flag.BoolVar(&options.Debug, "debug", false, "Allow debugging of request/responses")
	flag.BoolVar(&options.UpdateTemplates, "update-templates", false, "Update Templates updates the installed templates (optional)")
	flag.StringVar(&options.TraceLogFile, "trace-log", "", "File to write sent requests trace log")
	flag.StringVar(&options.TemplatesDirectory, "update-directory", "", "Directory to use for storing nuclei-templates")
	flag.BoolVar(&options.JSON, "json", false, "Write json output to files")
	flag.BoolVar(&options.JSONRequests, "include-rr", false, "Write requests/responses for matches in JSON output")
	flag.BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan")
	flag.BoolVar(&options.TemplateList, "tl", false, "List available templates")
	flag.IntVar(&options.RateLimit, "rate-limit", 150, "Rate-Limit (maximum requests/second")
	flag.BoolVar(&options.StopAtFirstMatch, "stop-at-first-match", false, "Stop processing http requests at first match (this may break template/workflow logic)")
	flag.IntVar(&options.BulkSize, "bulk-size", 25, "Maximum Number of hosts analyzed in parallel per template")
	flag.IntVar(&options.TemplateThreads, "c", 10, "Maximum Number of templates executed in parallel")
	flag.BoolVar(&options.Project, "project", false, "Use a project folder to avoid sending same request multiple times")
	flag.StringVar(&options.ProjectPath, "project-path", "", "Use a user defined project folder, temporary folder is used if not specified but enabled")
	flag.BoolVar(&options.NoMeta, "no-meta", false, "Don't display metadata for the matches")
	flag.BoolVar(&options.TemplatesVersion, "templates-version", false, "Shows the installed nuclei-templates version")
	flag.StringVar(&options.BurpCollaboratorBiid, "burp-collaborator-biid", "", "Burp Collaborator BIID")
	flag.Parse()

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}
	if options.TemplatesVersion {
		config, err := readConfiguration()
		if err != nil {
			gologger.Fatalf("Could not read template configuration: %s\n", err)
		}
		gologger.Infof("Current nuclei-templates version: %s (%s)\n", config.CurrentVersion, config.TemplatesDirectory)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatalf("Program exiting: %s\n", err)
	}

	return options
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	if !options.TemplateList {
		// Check if a list of templates was provided and it exists
		if len(options.Templates) == 0 && !options.UpdateTemplates {
			return errors.New("no template/templates provided")
		}

		if options.Targets == "" && !options.Stdin && options.Target == "" && !options.UpdateTemplates {
			return errors.New("no target input provided")
		}
	}

	// Validate proxy options if provided
	err := validateProxyURL(
		options.ProxyURL,
		"invalid http proxy format (It should be http://username:password@host:port)",
	)
	if err != nil {
		return err
	}

	err = validateProxyURL(
		options.ProxySocksURL,
		"invalid socks proxy format (It should be socks5://username:password@host:port)",
	)
	if err != nil {
		return err
	}

	return nil
}

func validateProxyURL(proxyURL, message string) error {
	if proxyURL != "" && !isValidURL(proxyURL) {
		return errors.New(message)
	}

	return nil
}

func isValidURL(urlString string) bool {
	_, err := url.Parse(urlString)

	return err == nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}

	if options.NoColor {
		gologger.UseColors = false
	}

	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
