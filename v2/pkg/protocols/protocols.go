package protocols

import "github.com/projectdiscovery/nuclei/v2/pkg/output"

// RequestGenerator is an interface implemented by request generator for a protocol.
type RequestGenerator interface {
	// Next returns the next request in queue for the generator interface.
	// If no requests are remaining, next returns io.EOF error.
	Next() (interface{}, error)
	// Compile compiles the request generators preparing any requests possible.
	Compile() error
	// Requests returns the total number of requests the rule will perform
	Requests() int64
}

// Executer executes requests from a generator and returns an output event.
type Executer interface {
	// Execute executes the generator requests and returns an output event channel.
	Execute(generator RequestGenerator, callback OutputEventCallback) error
}

// OutputEventCallback is a callback for each recieved output from executor
type OutputEventCallback func(event output.Event)
