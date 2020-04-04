package runner

import (
	"errors"

	"github.com/projectdiscovery/gologger"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Check if a list of resolvers was provided and it exists
	if options.Templates == "" {
		return errors.New("no template/templates provided")
	}

	if options.Targets == "" && !options.Stdin {
		return errors.New("no target input provided")
	}
	return nil
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
