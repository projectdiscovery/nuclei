package generic

import (
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	mapsutil "github.com/projectdiscovery/utils/maps"
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
func (g *Generic) ExecuteWithResults(ctx *scan.ScanContext) error {
	dynamicValues := make(map[string]interface{})
	if ctx.Input.HasArgs() {
		ctx.Input.ForEach(func(key string, value interface{}) {
			dynamicValues[key] = value
		})
	}
	previous := mapsutil.NewSyncLockMap[string, any]()

	for _, req := range g.requests {
		select {
		case <-ctx.Context().Done():
			return ctx.Context().Err()
		default:
		}

		inputItem := ctx.Input.Clone()
		if g.options.InputHelper != nil && ctx.Input.MetaInput.Input != "" {
			if inputItem.MetaInput.Input = g.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
				return nil
			}
		}

		err := req.ExecuteWithResults(inputItem, dynamicValues, output.InternalEvent(previous.GetAll()), func(event *output.InternalWrappedEvent) {
			// this callback is not concurrent safe so mutex should be used to synchronize
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
					_ = previous.Set(builder.String(), v)
					builder.Reset()
				}
			}
			if event.HasOperatorResult() {
				g.results.CompareAndSwap(false, true)
			}
			// for ExecuteWithResults : this callback will execute user defined callback and some error handling
			// for Execute : this callback will print the result to output
			ctx.LogEvent(event)
		})
		if err != nil {
			ctx.LogError(err)
			gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n", g.options.TemplateID, ctx.Input.MetaInput.PrettyPrint(), err)
		}
		if g.options.HostErrorsCache != nil {
			g.options.HostErrorsCache.MarkFailedOrRemove(g.options.ProtocolType.String(), ctx.Input, err)
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
