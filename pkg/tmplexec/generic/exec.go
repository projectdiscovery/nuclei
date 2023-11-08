package generic

import (
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// generic engine as name suggests is a generic template
// execution engine and executes all requests one after another
// without any logic in between
type Generic struct {
	requests []protocols.Request
	options  *protocols.ExecutorOptions
	results  *atomic.Bool
}

// NewGenericEngine creates a new generic engine from a list of requests
func NewGenericEngine(requests []protocols.Request, options *protocols.ExecutorOptions, results *atomic.Bool) *Generic {
	if results == nil {
		results = &atomic.Bool{}
	}
	return &Generic{requests: requests, options: options, results: results}
}

// Compile engine specific compilation
func (g *Generic) Compile() error {
	// protocol/ request is already handled by template executer
	return nil
}

// ExecuteWithResults executes the template and returns results
func (g *Generic) ExecuteWithResults(input *contextargs.Context, callback protocols.OutputEventCallback) error {
	dynamicValues := make(map[string]interface{})
	if input.HasArgs() {
		input.ForEach(func(key string, value interface{}) {
			dynamicValues[key] = value
		})
	}
	previous := make(map[string]interface{})

	for _, req := range g.requests {
		inputItem := input.Clone()
		if g.options.InputHelper != nil && input.MetaInput.Input != "" {
			if inputItem.MetaInput.Input = g.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
				return nil
			}
		}

		err := req.ExecuteWithResults(inputItem, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			if event == nil {
				// ideally this should never happen since protocol exits on error and callback is not called
				return
			}
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
			if event.HasOperatorResult() {
				g.results.CompareAndSwap(false, true)
			}
			// for ExecuteWithResults : this callback will execute user defined callback and some error handling
			// for Execute : this callback will print the result to output
			callback(event)
		})
		if err != nil {
			if g.options.HostErrorsCache != nil {
				g.options.HostErrorsCache.MarkFailed(input.MetaInput.ID(), err)
			}
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", g.options.TemplateID, input.MetaInput.PrettyPrint(), err)
		}
		// If a match was found and stop at first match is set, break out of the loop and return
		if g.results.Load() && (g.options.StopAtFirstMatch || g.options.Options.StopAtFirstMatch) {
			break
		}
	}
	return nil
}

// Type returns the type of engine
func (g *Generic) Name() string {
	return "generic"
}
