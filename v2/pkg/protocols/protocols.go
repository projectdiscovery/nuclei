package protocols

import (
	"go.uber.org/ratelimit"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Executer is an interface implemented any protocol based request executer.
type Executer interface {
	// Compile compiles the execution generators preparing any requests possible.
	Compile() error
	// Requests returns the total number of requests the rule will perform
	Requests() int
	// Execute executes the protocol group and returns true or false if results were found.
	Execute(input string) (bool, error)
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	ExecuteWithResults(input string, callback OutputEventCallback) error
}

// ExecuterOptions contains the configuration options for executer clients
type ExecuterOptions struct {
	// TemplateID is the ID of the template for the request
	TemplateID string
	// TemplatePath is the path of the template for the request
	TemplatePath string
	// TemplateInfo contains information block of the template request
	TemplateInfo model.Info
	// Output is a writer interface for writing output events from executer.
	Output output.Writer
	// Options contains configuration options for the executer.
	Options *types.Options
	// IssuesClient is a client for nuclei issue tracker reporting
	IssuesClient *reporting.Client
	// Progress is a progress client for scan reporting
	Progress progress.Progress
	// RateLimiter is a rate-limiter for limiting sent number of requests.
	RateLimiter ratelimit.Limiter
	// Catalog is a template catalog implementation for nuclei
	Catalog *catalog.Catalog
	// ProjectFile is the project file for nuclei
	ProjectFile *projectfile.ProjectFile
	// Browser is a browser engine for running headless templates
	Browser *engine.Browser
	// Interactsh is a client for interactsh oob polling server
	Interactsh *interactsh.Client
	// HostErrorsCache is an optional cache for handling host errors
	HostErrorsCache *hosterrorscache.Cache

	Operators []*operators.Operators // only used by offlinehttp module

	WorkflowLoader model.WorkflowLoader
}

// Request is an interface implemented any protocol based request generator.
type Request interface {
	// Compile compiles the request generators preparing any requests possible.
	Compile(options *ExecuterOptions) error
	// Requests returns the total number of requests the rule will perform
	Requests() int
	// GetID returns the ID for the request if any. IDs are used for multi-request
	// condition matching. So, two requests can be sent and their match can
	// be evaluated from the third request by using the IDs for both requests.
	GetID() string
	// Match performs matching operation for a matcher on model and returns:
	// true and a list of matched snippets if the matcher type is supports it
	// otherwise false and an empty string slice
	Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
	// Extract performs extracting operation for an extractor on model and returns true or false.
	Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
	ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
	// MakeResultEventItem creates a result event from internal wrapped event. Intended to be used by MakeResultEventItem internally
	MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
	// MakeResultEvent creates a flat list of result events from an internal wrapped event, based on successful matchers and extracted data
	MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
	// GetCompiledOperators returns a list of the compiled operators
	GetCompiledOperators() []*operators.Operators
}

// OutputEventCallback is a callback event for any results found during scanning.
type OutputEventCallback func(result *output.InternalWrappedEvent)

func MakeDefaultResultEvent(request Request, wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 && !wrapped.OperatorsResult.Matched {
		return nil
	}

	results := make([]*output.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for matcherNames := range wrapped.OperatorsResult.Matches {
			data := request.MakeResultEventItem(wrapped)
			data.MatcherName = matcherNames
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := request.MakeResultEventItem(wrapped)
			data.ExtractorName = k
			data.ExtractedResults = v
			results = append(results, data)
		}
	} else {
		data := request.MakeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}
