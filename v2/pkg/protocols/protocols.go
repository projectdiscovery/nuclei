package protocols

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"go.uber.org/ratelimit"
)

// Executer is an interface implemented any protocol based request generator.
type Executer interface {
	// Compile compiles the request generators preparing any requests possible.
	Compile(options ExecuterOptions) error
	// Requests returns the total number of requests the rule will perform
	Requests() int64
	// Match performs matching operation for a matcher on model and returns true or false.
	Match(data map[string]interface{}, matcher *matchers.Matcher) bool
	// Extract performs extracting operation for a extractor on model and returns true or false.
	Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	// Execute executes the protocol requests and returns true or false if results were found.
	Execute(input string) (bool, error)
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	ExecuteWithResults(input string) ([]output.InternalWrappedEvent, error)
}

// ExecuterOptions contains the configuration options for executer clients
type ExecuterOptions struct {
	// TemplateID is the ID of the template for the request
	TemplateID string
	// TemplateInfo contains information block of the template request
	TemplateInfo map[string]string
	// Output is a writer interface for writing output events from executer.
	Output output.Writer
	// Options contains configuration options for the executer.
	Options *types.Options
	// RateLimiter is a rate-limiter for limiting sent number of requests.
	RateLimiter ratelimit.Limiter
}
