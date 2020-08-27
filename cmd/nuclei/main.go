package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	nucleiRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	nucleiRunner.RunEnumeration()
	nucleiRunner.Close()
}
