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
	input          *contextargs.Context
	allProtocols   map[string][]protocols.Request
	options        *protocols.ExecutorOptions
	allErrs        mapsutil.SyncLockMap[string, error]
	results        *atomic.Bool
	jsVM           *goja.Runtime
	program        *goja.Program
	protoFunctions map[string]func(id ...string) // reqFunctions contains functions that allow executing requests/protocols from js
}

// Init initializes the flow executor all dependencies
// this compiles and prepares for execution of a flow
// since it has dependencies on variables and etc it can't be done moved to templates package
func (f *FlowExecutor) Compile(callback func(event *output.InternalWrappedEvent)) error {
	if f.results == nil {
		f.results = new(atomic.Bool)
	}
	// store all dynamic variables and other variables here
	f.options.TemplateCtx = contextargs.New()
	// create a new js vm/runtime
	f.jsVM = goja.New()

	// -----Load all types of variables-----
	// add all input args to template context
	if f.input.HasArgs() {
		f.input.ForEach(func(key string, value interface{}) {
			f.options.TemplateCtx.Set(key, value)
		})
	}
	// load all variables and evaluate with existing data
	variableMap := f.options.Variables.Evaluate(f.options.TemplateCtx.GetAll())
	// cli options
	optionVars := generators.BuildPayloadFromOptions(f.options.Options)
	// constants
	constants := f.options.Constants
	allVars := generators.MergeMaps(variableMap, constants, optionVars)
	// we support loading variables from files in variables , cli options and constants
	// try to load if files exist
	for k, v := range allVars {
		if str, ok := v.(string); ok && len(str) < 150 && fileutil.FileExists(str) {
			if value, err := f.ReadDataFromFile(str); err == nil {
				allVars[k] = value
			}
		}
	}
	f.options.TemplateCtx.Merge(allVars)
	// ------

	// ---- define callback functions/objects----
	f.protoFunctions = map[string]func(id ...string){}
	compileErrors := []error{}

	for proto, requests := range f.allProtocols {
		reqMap := mapsutil.Map[string, protocols.Request]{}
		counter := 0
		for index := range requests {
			request := f.allProtocols[proto][index]
			if request.GetID() != "" {
				// if id is present use it
				reqMap[request.GetID()] = request
			}
			// fallback to using index as id
			// always allow index as id as a fallback
			reqMap[strconv.Itoa(counter)] = request
			counter++
		}
		// ---define hook that allows protocol/request execution from js-----
		f.protoFunctions[proto] = func(ids ...string) {
			defer func() {
				// to avoid polling update template variables everytime we execute a protocol
				var m map[string]interface{} = f.options.TemplateCtx.GetAll()
				_ = f.jsVM.Set("template", m)
			}()
			// if no id is passed execute all requests in sequence
			if len(ids) == 0 {
				// execution logic for http()/dns() etc
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
							_ = f.jsVM.Set("template", f.options.TemplateCtx.GetAll())
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

	// register all built in functions
	return f.RegisterBuiltInFunctions()
}

// RegisterBuiltInFunctions registers all built in functions for the flow
func (f *FlowExecutor) RegisterBuiltInFunctions() error {
	// currently we register following builtin functions
	// log -> log to stdout with [JS] prefix should only be used for debugging
	// set -> set a variable in template context
	// proto(arg ...String) <- this is generic syntax of how a protocol/request binding looks in js
	// we only register only those protocols that are available in template

	// we also register a map datatype called template with all template variables
	// template -> all template variables are available in js template object

	if err := f.jsVM.Set("log", func(call goja.FunctionCall) goja.Value {
		// TODO: verify string interpolation and handle multiple args
		arg := call.Argument(0).Export()
		gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), arg)
		return goja.Null()
	}); err != nil {
		return err
	}

	if err := f.jsVM.Set("set", func(call goja.FunctionCall) goja.Value {
		varName := call.Argument(0).Export()
		varValue := call.Argument(1).Export()
		f.options.TemplateCtx.Set(varName.(string), varValue)
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
	for name, fn := range f.protoFunctions {
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
	_, err := f.jsVM.RunProgram(f.program)
	if err != nil {
		return false, errorutil.NewWithErr(err).Msgf("failed to execute flow\n%v\n", f.options.Flow)
	}
	return f.results.Load(), nil
}

// ReadDataFromFile reads data from file respecting sandbox options
func (f *FlowExecutor) ReadDataFromFile(payload string) ([]string, error) {
	values := []string{}
	// load file respecting sandbox
	reader, err := f.options.Options.LoadHelperFile(payload, f.options.TemplatePath, f.options.Catalog)
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
