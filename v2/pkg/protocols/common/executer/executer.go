package executer

import (
	"fmt"
	"strings"
	"time"

	"github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
)

// Executer executes a group of requests for a protocol
type Executer struct {
	requests           []protocols.Request
	options            *protocols.ExecuterOptions
	matcherStatusItems *ccache.Cache
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []protocols.Request, options *protocols.ExecuterOptions) *Executer {
	return &Executer{requests: requests, options: options, matcherStatusItems: ccache.New(ccache.Configure())}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	cliOptions := e.options.Options

	for _, request := range e.requests {
		if err := request.Compile(e.options); err != nil {
			var dslCompilationError *dsl.CompilationError
			if errors.As(err, &dslCompilationError) {
				if cliOptions.Verbose {
					rawErrorMessage := dslCompilationError.Error()
					formattedErrorMessage := strings.ToUpper(rawErrorMessage[:1]) + rawErrorMessage[1:] + "."
					gologger.Warning().Msgf(formattedErrorMessage)
					gologger.Info().Msgf("The available custom DSL functions are:")
					fmt.Println(dsl.GetPrintableDslFunctionSignatures(cliOptions.NoColor))
				}
			}
			return err
		}
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// holds the console request filter data
type stdIORequestFilter struct {
	hasAnyMatched bool
	currentIndex  int
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input *contextargs.Context) (bool, error) {
	var results bool

	dynamicValues := make(map[string]interface{})
	if input.HasArgs() {
		input.ForEach(func(key string, value interface{}) {
			dynamicValues[key] = value
		})
	}
	previous := make(map[string]interface{})
	var totalRequest = e.Requests()
	for _, req := range e.requests {
		inputItem := *input
		if e.options.InputHelper != nil && input.Input != "" {
			if inputItem.Input = e.options.InputHelper.Transform(input.Input, req.Type()); inputItem.Input == "" {
				return false, nil
			}
		}

		err := req.ExecuteWithResults(&inputItem, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					previous[builder.String()] = v
					builder.Reset()
				}
			}

			var (
				templateID string
				host       string
			)
			if event.OperatorsResult == nil {
				templateID = types.ToString(event.InternalEvent["template-id"])
				host = types.ToString(event.InternalEvent["host"])
			} else {
				for _, d := range event.Results {
					templateID = d.TemplateID
					host = d.Host
					break
				}
			}
			id := fmt.Sprintf("%s-%s", templateID, host)
			item := e.matcherStatusItems.Get(id)
			var filter stdIORequestFilter
			if item != nil {
				filter = item.Value().(stdIORequestFilter)
				filter.currentIndex++
				e.matcherStatusItems.Replace(id, filter)
			} else {
				filter = stdIORequestFilter{currentIndex: 1}
				e.matcherStatusItems.Set(id, filter, time.Second*60)
			}
			// If no results were found, and also interactsh is not being used
			// in that case we can skip it, otherwise we've to show failure in
			// case of matcher-status flag.
			if event.OperatorsResult == nil && !event.UsesInteractsh {
				if !filter.hasAnyMatched && filter.currentIndex == totalRequest {
					if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
						gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
					}
				}
			} else {
				if writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient) {
					filter.hasAnyMatched = true
					e.matcherStatusItems.Replace(id, filter)
					results = true
				} else {
					if !filter.hasAnyMatched && filter.currentIndex == totalRequest {
						if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
							gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
						}
					}
				}
			}
		})
		if err != nil {
			if e.options.HostErrorsCache != nil {
				e.options.HostErrorsCache.MarkFailed(input.Input, err)
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", e.options.TemplateID, input.Input, err)
		}
		// If a match was found and stop at first match is set, break out of the loop and return
		if results && (e.options.StopAtFirstMatch || e.options.Options.StopAtFirstMatch) {
			break
		}
	}
	return results, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input *contextargs.Context, callback protocols.OutputEventCallback) error {
	dynamicValues := make(map[string]interface{})
	if input.HasArgs() {
		input.ForEach(func(key string, value interface{}) {
			dynamicValues[key] = value
		})
	}
	previous := make(map[string]interface{})
	var totalRequest = e.Requests()
	var results bool

	for _, req := range e.requests {
		req := req

		inputItem := *input
		if e.options.InputHelper != nil && input.Input != "" {
			if inputItem.Input = e.options.InputHelper.Transform(input.Input, req.Type()); inputItem.Input == "" {
				return nil
			}
		}

		err := req.ExecuteWithResults(&inputItem, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					previous[builder.String()] = v
					builder.Reset()
				}
			}
			var (
				templateID string
				host       string
			)

			if event.OperatorsResult == nil {
				templateID = types.ToString(event.InternalEvent["template-id"])
				host = types.ToString(event.InternalEvent["host"])
			} else {
				for _, d := range event.Results {
					templateID = d.TemplateID
					host = d.Host
					break
				}
			}
			id := fmt.Sprintf("%s-%s", templateID, host)
			item := e.matcherStatusItems.Get(id)
			var filter stdIORequestFilter
			if item != nil {
				filter = item.Value().(stdIORequestFilter)
				filter.currentIndex++
				e.matcherStatusItems.Replace(id, filter)
			} else {
				filter = stdIORequestFilter{currentIndex: 1}
				e.matcherStatusItems.Set(id, filter, time.Second*60)
			}
			if event.OperatorsResult == nil {
				if !filter.hasAnyMatched && filter.currentIndex == totalRequest {
					if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
						gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
					}
				}
			} else {
				filter.hasAnyMatched = true
				e.matcherStatusItems.Replace(id, filter)
				results = true
				callback(event)
			}
		})
		if err != nil {
			if e.options.HostErrorsCache != nil {
				e.options.HostErrorsCache.MarkFailed(input.Input, err)
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", e.options.TemplateID, input.Input, err)
		}
		// If a match was found and stop at first match is set, break out of the loop and return
		if results && (e.options.StopAtFirstMatch || e.options.Options.StopAtFirstMatch) {
			break
		}
	}
	return nil
}
