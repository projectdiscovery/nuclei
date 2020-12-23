package protocols

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Executer is an interface implemented any protocol based request generator.
type Executer interface {
	// Compile compiles the request generators preparing any requests possible.
	Compile(options ExecuterOptions) error
	// Requests returns the total number of requests the rule will perform
	Requests() int64
	// Execute executes the protocol requests and returns an output event channel.
	Execute(input string) (bool, error)
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	ExecuteWithResults(input string) ([]output.Event, error)
}

// ExecuterOptions contains the configuration options for executer clients
type ExecuterOptions struct {
	// Output is a writer interface for writing output events from executer.
	Output output.Writer
	// Options contains configuration options for the executer
	Options *types.Options
}
