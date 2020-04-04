package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the template requesting process.
type Options struct {
	Templates string // Signature specifies the template/templates to use
	Targets   string // Targets specifies the targets to scan using templates.
	Threads   int    // Thread controls the number of concurrent requests to make.
	Timeout   int    // Timeout is the seconds to wait for a response from the server.
	Output    string // Output is the file to write found subdomains to.
	Silent    bool   // Silent suppresses any extra text and only writes found URLs on screen.
	Version   bool   // Version specifies if we should just show version and exit
	Verbose   bool   // Verbose flag indicates whether to show verbose output or not
	NoColor   bool   // No-Color disables the colored output.

	Stdin bool // Stdin specifies whether stdin input was given to the process
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.Templates, "f", "", "Template/templates to use during enumeration")
	flag.StringVar(&options.Targets, "l", "", "Targets to scan using templates during enumeration")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output")
	flag.BoolVar(&options.Version, "version", false, "Show version of shuffledns")
	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Threads, "t", 100, "Number of concurrent requests to make")
	flag.IntVar(&options.Timeout, "timeout", 30, "Time to wait in seconds before timeout")

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
