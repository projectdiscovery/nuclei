package executer

import (
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/executer/builtin"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"go.uber.org/multierr"
)

var (
	ErrInvalidRequestID = errorutil.NewWithFmt("invalid request id '%s' provided")
)

type ProtoOptions struct {
	Hide  bool
	Async bool
}

func GetProtoOptions(m map[string]interface{}) *ProtoOptions {
	options := &ProtoOptions{
		Hide:  GetBool(m["hide"]),
		Async: GetBool(m["async"]),
	}
	return options
}

type FlowExecutor struct {
	input          *contextargs.Context
	allProtocols   map[string][]protocols.Request
	options        *protocols.ExecutorOptions
	allErrs        mapsutil.SyncLockMap[string, error]
	results        *atomic.Bool
	jsVM           *goja.Runtime
	program        *goja.Program
	protoFunctions map[string]func(call goja.FunctionCall) goja.Value // reqFunctions contains functions that allow executing requests/protocols from js
	wg             sync.WaitGroup
}

// Init initializes the flow executor all dependencies
// this compiles and prepares for execution of a flow
// since it has dependencies on variables and etc it can't be done moved to templates package
func (f *FlowExecutor) Compile(callback func(event *output.InternalWrappedEvent)) error {
	if f.results == nil {
		f.results = new(atomic.Bool)
	}
	// store all dynamic variables and other variables here
	if f.options.TemplateCtx == nil {
		f.options.TemplateCtx = contextargs.New()
	}
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
			} else {
				gologger.Warning().Msgf("could not load file '%s' for variable '%s': %s", str, k, err)
			}
		}
	}
	f.options.TemplateCtx.Merge(allVars)
	// ------

	// ---- define callback functions/objects----
	f.protoFunctions = map[string]func(call goja.FunctionCall) goja.Value{}
	compileErrors := []error{}

	for p, requests := range f.allProtocols {
		reqMap := mapsutil.Map[string, protocols.Request]{}
		counter := 0
		proto := strings.ToLower(p) // donot use loop variables in callback functions directly
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
		f.protoFunctions[proto] = func(call goja.FunctionCall) goja.Value {
			ids := []string{}
			opts := &ProtoOptions{}
			for _, v := range call.Arguments {
				switch value := v.Export().(type) {
				case map[string]interface{}:
					opts = GetProtoOptions(value)
				default:
					ids = append(ids, types.ToString(value))
				}
			}
			if opts.Async {
				f.wg.Add(1)
				defer f.wg.Done()
			}
			defer func() {
				// to avoid polling update template variables everytime we execute a protocol
				var m map[string]interface{} = f.options.TemplateCtx.GetAll()
				_ = f.jsVM.Set("template", m)
			}()
			matcherStatus := &atomic.Bool{} // due to interactsh matcher polling logic this needs to be atomic bool

			// if no id is passed execute all requests in sequence
			if len(ids) == 0 {
				// execution logic for http()/dns() etc
				for index := range f.allProtocols[proto] {
					req := f.allProtocols[proto][index]
					err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.TemplateCtx.GetAll()), nil, func(result *output.InternalWrappedEvent) {
						if result != nil {
							f.results.CompareAndSwap(false, true)
							if !opts.Hide {
								callback(result)
							}
							// export dynamic values from operators (i.e internal:true)
							// add add it to template context
							// this is a conflicting behaviour with iterate-all
							if result.HasOperatorResult() {
								matcherStatus.CompareAndSwap(false, result.OperatorsResult.Matched)
								if !result.OperatorsResult.Matched && !hasMatchers(req.GetCompiledOperators()) {
									// if matcher status is false . check if template/request contains any matcher at all
									// if it does then we need to set matcher status to true
									matcherStatus.CompareAndSwap(false, true)
								}
								if len(result.OperatorsResult.DynamicValues) > 0 {
									for k, v := range result.OperatorsResult.DynamicValues {
										f.options.TemplateCtx.Set(k, v)
									}
								}
							}
						}
					})
					// fmt.Printf("done executing %v with index %v and err %v", proto, index, err)
					if err != nil {
						// save all errors in a map with id as key
						// its less likely that there will be race condition but just in case
						id := req.GetID()
						if id == "" {
							id, _ = reqMap.GetKeyWithValue(req)
						}
						err = f.allErrs.Set(proto+":"+id, err)
						if err != nil {
							gologger.Error().Msgf("failed to store flow runtime errors got %v", err)
						}
						return f.jsVM.ToValue(matcherStatus.Load())
					}
				}
				return f.jsVM.ToValue(matcherStatus.Load())
			}

			// execution logic for http("0") or http("get-aws-vpcs")
			for _, id := range ids {
				req, ok := reqMap[id]
				if !ok {
					gologger.Error().Msgf("invalid request id '%s' provided", id)
					// compile error
					compileErrors = append(compileErrors, ErrInvalidRequestID.Msgf(id))
					return f.jsVM.ToValue(matcherStatus.Load())
				}
				err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.TemplateCtx.GetAll()), nil, func(result *output.InternalWrappedEvent) {
					if result != nil {
						f.results.CompareAndSwap(false, true)
						if !opts.Hide {
							callback(result)
						}
						// export dynamic values from operators (i.e internal:true)
						// add add it to template context
						if result.HasOperatorResult() {
							matcherStatus.CompareAndSwap(false, result.OperatorsResult.Matched)
							if len(result.OperatorsResult.DynamicValues) > 0 {
								for k, v := range result.OperatorsResult.DynamicValues {
									f.options.TemplateCtx.Set(k, v)
								}
								_ = f.jsVM.Set("template", f.options.TemplateCtx.GetAll())
							}
						}
					}
				})
				if err != nil {
					index := id
					err = f.allErrs.Set(proto+":"+index, err)
					if err != nil {
						gologger.Error().Msgf("failed to store flow runtime errors got %v", err)
					}
				}
			}
			return f.jsVM.ToValue(matcherStatus.Load())
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
		switch value := arg.(type) {
		case string:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
		case map[string]interface{}:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), vardump.DumpVariables(value))
		default:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
		}
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

	// iterate provides global iterator function by handling null values or strings
	if err := f.jsVM.Set("iterate", func(call goja.FunctionCall) goja.Value {
		allVars := []any{}
		for _, v := range call.Arguments {
			if v.Export() == nil {
				continue
			}
			if v.ExportType().Kind() == reflect.Slice {
				// convert []datatype to []interface{}
				// since it cannot be type asserted to []interface{} directly
				rfValue := reflect.ValueOf(v.Export())
				for i := 0; i < rfValue.Len(); i++ {
					allVars = append(allVars, rfValue.Index(i).Interface())
				}
			} else {
				allVars = append(allVars, v.Export())
			}
		}
		return f.jsVM.ToValue(allVars)
	}); err != nil {
		return err
	}

	// unfortunately js doesn't have trimLeft/trimRight
	if err := f.jsVM.Set("trimLeft", func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		char := call.Argument(1).String()
		if char == "" {
			char = " "
		}
		return f.jsVM.ToValue(strings.TrimLeft(value, char))
	}); err != nil {
		return err
	}

	if err := f.jsVM.Set("trimRight", func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		char := call.Argument(1).String()
		if char == "" {
			char = " "
		}
		return f.jsVM.ToValue(strings.TrimRight(value, char))
	}); err != nil {
		return err
	}

	if err := f.jsVM.Set("trim", func(call goja.FunctionCall) goja.Value {
		value := call.Argument(0).String()
		char := call.Argument(1).String()
		if char == "" {
			char = " "
		}
		return f.jsVM.ToValue(strings.Trim(value, char))
	}); err != nil {
		return err
	}

	// add a builtin dedupe object
	if err := f.jsVM.Set("Dedupe", func(call goja.ConstructorCall) *goja.Object {
		d := builtin.NewDedupe(f.jsVM)
		obj := call.This
		obj.Set("Add", d.Add)
		obj.Set("Values", d.Values)
		return nil
	}); err != nil {
		return err
	}

	var m = f.options.TemplateCtx.GetAll()
	if m == nil {
		m = map[string]interface{}{}
	}

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
	value, err := f.jsVM.RunProgram(f.program)
	if err != nil {
		return false, errorutil.NewWithErr(err).Msgf("failed to execute flow\n%v\n", f.options.Flow)
	}
	f.wg.Wait()
	runtimeErr := f.GetRuntimeErrors()
	if runtimeErr != nil {
		return false, errorutil.NewWithErr(runtimeErr).Msgf("got following errors while executing flow")
	}
	if value.Export() != nil {
		return value.ToBoolean(), nil
	}
	return f.results.Load(), nil
}

func (f *FlowExecutor) GetRuntimeErrors() error {
	errs := []error{}
	for proto, err := range f.allErrs.GetAll() {
		errs = append(errs, errorutil.NewWithErr(err).Msgf("failed to execute %v protocol", proto))
	}
	return multierr.Combine(errs...)
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

// Checks if template has matchers
func hasMatchers(all []*operators.Operators) bool {
	for _, operator := range all {
		if len(operator.Matchers) > 0 {
			return true
		}
	}
	return false
}

// GetBool returns bool value from interface
func GetBool(value interface{}) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	default:
		tmpValue := types.ToString(value)
		if strings.EqualFold(tmpValue, "true") {
			return true
		}
	}
	return false
}
