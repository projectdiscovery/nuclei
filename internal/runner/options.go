package runner

import (
	"errors"
	"flag"
	"net/url"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// Options contains the configuration options for tuning
// the template requesting process.
type Options struct {
	Debug             bool // Debug mode allows debugging request/responses for the engine
	Silent            bool // Silent suppresses any extra text and only writes found URLs on screen.
	Version           bool // Version specifies if we should just show version and exit
	Verbose           bool // Verbose flag indicates whether to show verbose output or not
	NoColor           bool // No-Color disables the colored output.
	UpdateTemplates   bool // UpdateTemplates updates the templates installed at startup
	JSON              bool // JSON writes json output to files
	JSONRequests      bool // write requests/responses for matches in JSON output
	EnableProgressBar bool // Enable progrss bar
	TemplateList      bool // List available templates

	Stdin              bool                   // Stdin specifies whether stdin input was given to the process
	Templates          multiStringFlag        // Signature specifies the template/templates to use
	ExcludedTemplates  multiStringFlag        // Signature specifies the template/templates to exclude
	Severity           string                 // Filter templates based on their severity and only run the matching ones.
	Target             string                 // Target is a single URL/Domain to scan usng a template
	Targets            string                 // Targets specifies the targets to scan using templates.
	Threads            int                    // Thread controls the number of concurrent requests to make.
	Timeout            int                    // Timeout is the seconds to wait for a response from the server.
	Retries            int                    // Retries is the number of times to retry the request
	Output             string                 // Output is the file to write found subdomains to.
	ProxyURL           string                 // ProxyURL is the URL for the proxy server
	ProxySocksURL      string                 // ProxySocksURL is the URL for the proxy socks server
	CustomHeaders      requests.CustomHeaders // Custom global headers
	TemplatesDirectory string                 // TemplatesDirectory is the directory to use for storing templates
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return ""
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

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
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Threads, "c", 50, "Number of concurrent requests to make")
	flag.IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout")
	flag.IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request")
	flag.Var(&options.CustomHeaders, "H", "Custom Header.")
	flag.BoolVar(&options.Debug, "debug", false, "Allow debugging of request/responses")
	flag.BoolVar(&options.UpdateTemplates, "update-templates", false, "Update Templates updates the installed templates (optional)")
	flag.StringVar(&options.TemplatesDirectory, "update-directory", "", "Directory to use for storing nuclei-templates")
	flag.BoolVar(&options.JSON, "json", false, "Write json output to files")
	flag.BoolVar(&options.JSONRequests, "json-requests", false, "Write requests/responses for matches in JSON output")
	flag.BoolVar(&options.EnableProgressBar, "pbar", false, "Enable the progress bar")
	flag.BoolVar(&options.TemplateList, "tl", false, "List available templates")

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

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatalf("Program exiting: %s\n", err)
	}

	return options
}

func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	}

	return true
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
