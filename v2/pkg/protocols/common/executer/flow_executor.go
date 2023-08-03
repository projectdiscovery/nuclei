package executer

import (
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
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
	jsVM         *goja.Runtime
	program      *goja.Program
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

	// create a new js vm/runtime
	f.jsVM = goja.New()

	// add all input args to template context
	if f.input.HasArgs() {
		f.input.ForEach(func(key string, value interface{}) error {
			f.options.TemplateCtx.Set(key, value)
			return nil
		})
	}
	f.options.TemplateCtx.Merge(f.options.Variables.GetAll())
	// cli options
	optionVars := generators.BuildPayloadFromOptions(f.options.Options)
	// constants
	constants := f.options.Constants
	allVars := generators.MergeMaps(optionVars, constants)
	f.options.TemplateCtx.Merge(allVars)
	// TODO: this is another sandbox bypass we only expand in generators.go
	// but we require it now in multiple places (move sandbox and payload read logic to config.DefaultConfig())
	// merge all variables
	for k, v := range f.options.TemplateCtx.GetAll() {
		if str, ok := v.(string); ok && len(str) < 150 && fileutil.FileExists(str) {
			if value, err := f.ReadDataFromFile(str); err == nil {
				f.options.TemplateCtx.Set(k, value)
			}
		}
	}

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
			defer func() {
				var m map[string]interface{} = f.options.TemplateCtx.GetAll()
				f.jsVM.Set("template", m)
			}()
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
							// this is a conflicting behaviour with iterate-all
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
					gologger.Error().Msgf("invalid request id '%s' provided", id)
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
							f.jsVM.Set("template", f.options.TemplateCtx.GetAll())
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

	if err := f.jsVM.Set("log", func(call goja.FunctionCall) goja.Value {
		arg := call.Argument(0).Export()
		gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), arg)
		return goja.Null()
	}); err != nil {
		return err
	}

	if err := f.jsVM.Set("poll", func(call goja.FunctionCall) goja.Value {
		var m map[string]interface{} = f.options.TemplateCtx.GetAll()
		f.jsVM.Set("template", m)
		return goja.Null()
	}); err != nil {
		return err
	}

	if err := f.jsVM.Set("set", func(call goja.FunctionCall) goja.Value {
		varName := call.Argument(0).Export()
		varValue := call.Argument(1).Export()
		f.options.TemplateCtx.Set(varName.(string), varValue)
		// gologger.Debug().Msgf("JS: set %s to %s", varName, varValue)
		// fmt.Printf("log: set %s to %s\n", varName, varValue)
		return goja.Null()
	}); err != nil {
		return err
	}

	var m map[string]interface{} = f.options.TemplateCtx.GetAll()

	if err := f.jsVM.Set("template", m); err != nil {
		// all template variables are available in js template object
		return err
	}

	// register all protocols
	for name, fn := range VarRegistry {
		if err := f.jsVM.Set(name, fn); err != nil {
			return err
		}
	}

	program, err := goja.Compile("flow", f.options.Flow, false)
	if err != nil {
		return err
	}
	f.program = program

	return nil
}

// Execute executes the flow
func (f *FlowExecutor) Execute() (bool, error) {
	// pass flow and execute the js vm and handle errors
	value, err := f.jsVM.RunProgram(f.program)
	if err != nil {
		return false, errorutil.NewWithErr(err).Msgf("failed to execute flow\n%v\n", f.options.Flow)
	}
	gologger.Verbose().Msgf("Flow result: %s", value.String())

	return f.results.Load(), nil
}

func (f *FlowExecutor) ReadDataFromFile(payload string) ([]string, error) {
	values := []string{}
	reader, err := f.options.Catalog.OpenFile(payload)
	if err != nil {
		return values, err
	}
	defer reader.Close()
	bin, err := io.ReadAll(reader)
	if err != nil {
		return values, err
	}
	for _, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			values = append(values, line)
		}
	}
	return values, nil
}
