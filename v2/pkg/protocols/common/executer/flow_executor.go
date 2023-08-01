package executer

import (
	"strconv"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"go.uber.org/multierr"
)

var (
	ErrInvalidRequestID = errorutil.NewWithFmt("invalid request id '%s' provided")
)

type FlowExecutor struct {
	input        *contextargs.Context
	allProtocols map[string][]protocols.Request
	options      *protocols.ExecutorOptions
	allErrs      mapsutil.SyncLockMap[string, error]
	results      *atomic.Bool
}

// Init initializes the flow executor all dependencies
// this compiles and prepares for execution of a flow
// since it has dependencies on variables and etc it can't be done moved to templates package
func (f *FlowExecutor) Compile(callback func(event *output.InternalWrappedEvent)) error {
	// define variables/objects
	VarRegistry := map[string]func(id ...string){}
	// store all dynamic variables and other variables here
	f.options.TemplateCtx = contextargs.New()

	if f.results == nil {
		f.results = new(atomic.Bool)
	}

	// add all input args to template context
	if f.input.HasArgs() {
		f.input.ForEach(func(key string, value interface{}) error {
			f.options.TemplateCtx.Set(key, value)
			return nil
		})
	}
	// variables
	f.options.Variables.ForEach(func(key string, value interface{}) {
		f.options.TemplateCtx.Set(key, value)
	})
	// cli options
	optionVars := generators.BuildPayloadFromOptions(f.options.Options)
	// constants
	constants := f.options.Constants
	allVars := generators.MergeMaps(optionVars, constants)
	// merge all variables
	f.options.TemplateCtx.Merge(allVars)

	compileErrors := []error{}

	for proto, requests := range f.allProtocols {
		reqMap := mapsutil.Map[string, protocols.Request]{}
		counter := 0
		for index := range requests {
			request := f.allProtocols[proto][index]
			if request.GetID() != "" {
				// if id is present use it
				reqMap[request.GetID()] = request
			} else {
				// fallback to using index as id
				reqMap[strconv.Itoa(counter)] = request
			}
			counter++
		}
		VarRegistry[proto] = func(ids ...string) {
			// if no id is passed execute all requests in sequence
			if len(ids) == 0 {
				// execution logic for http()
				for index := range f.allProtocols[proto] {
					req := f.allProtocols[proto][index]
					err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.TemplateCtx.GetAll()), nil, func(result *output.InternalWrappedEvent) {
						if result != nil {
							f.results.CompareAndSwap(false, true)
							callback(result)
							// export dynamic values from operators (i.e internal:true)
							// add add it to template context
							if result.HasOperatorResult() && len(result.OperatorsResult.DynamicValues) > 0 {
								for k, v := range result.OperatorsResult.DynamicValues {
									f.options.TemplateCtx.Set(k, v)
								}
							}
						}
					})
					if err != nil {
						// save all errors in a map with id as key
						// its less likely that there will be race condition but just in case
						id := req.GetID()
						if id == "" {
							id, _ = reqMap.GetKeyWithValue(req)
						}
						_ = f.allErrs.Set(id, err)
						return
					}
				}
				return
			}

			// execution logic for http("0") or http("get-aws-vpcs")
			for _, id := range ids {
				req, ok := reqMap[id]
				if !ok {
					// compile error
					compileErrors = append(compileErrors, ErrInvalidRequestID.Msgf(id))
					return
				}
				err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.TemplateCtx.GetAll()), nil, func(result *output.InternalWrappedEvent) {
					if result != nil {
						f.results.CompareAndSwap(false, true)
						callback(result)
						// export dynamic values from operators (i.e internal:true)
						// add add it to template context
						if result.HasOperatorResult() && len(result.OperatorsResult.DynamicValues) > 0 {
							for k, v := range result.OperatorsResult.DynamicValues {
								f.options.TemplateCtx.Set(k, v)
							}
						}
					}
				})
				if err != nil {
					index := id
					_ = f.allErrs.Set(index, err)
				}
			}
		}
	}

	if len(compileErrors) > 0 {
		return multierr.Combine(compileErrors...)
	}

	return nil
}

// Execute executes the flow
func (f *FlowExecutor) Execute() (bool, error) {
	// pass flow and execute the js vm and handle errors
	return f.results.Load(), nil
}
