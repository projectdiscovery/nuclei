package flow

import (
	"reflect"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow/builtin"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// contains all internal/unexported methods of flow

// requestExecutor executes a protocol/request and returns true if any matcher was found
func (f *FlowExecutor) requestExecutor(reqMap mapsutil.Map[string, protocols.Request], opts *ProtoOptions) bool {
	defer func() {
		// evaluate all variables after execution of each protocol
		variableMap := f.options.Variables.Evaluate(f.options.GetTemplateCtx(f.input.MetaInput).GetAll())
		f.options.GetTemplateCtx(f.input.MetaInput).Merge(variableMap) // merge all variables into template context

		// to avoid polling update template variables everytime we execute a protocol
		var m map[string]interface{} = f.options.GetTemplateCtx(f.input.MetaInput).GetAll()
		_ = f.jsVM.Set("template", m)
	}()
	matcherStatus := &atomic.Bool{} // due to interactsh matcher polling logic this needs to be atomic bool
	// if no id is passed execute all requests in sequence
	if len(opts.reqIDS) == 0 {
		// execution logic for http()/dns() etc
		for index := range f.allProtocols[opts.protoName] {
			req := f.allProtocols[opts.protoName][index]
			err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.GetTemplateCtx(f.input.MetaInput).GetAll()), nil, f.getProtoRequestCallback(req, matcherStatus, opts))
			if err != nil {
				// save all errors in a map with id as key
				// its less likely that there will be race condition but just in case
				id := req.GetID()
				if id == "" {
					id, _ = reqMap.GetKeyWithValue(req)
				}
				err = f.allErrs.Set(opts.protoName+":"+id, err)
				if err != nil {
					gologger.Error().Msgf("failed to store flow runtime errors got %v", err)
				}
				return matcherStatus.Load()
			}
		}
		return matcherStatus.Load()
	}

	// execution logic for http("0") or http("get-aws-vpcs")
	for _, id := range opts.reqIDS {
		req, ok := reqMap[id]
		if !ok {
			gologger.Error().Msgf("[%v] invalid request id '%s' provided", f.options.TemplateID, id)
			// compile error
			if err := f.allErrs.Set(opts.protoName+":"+id, ErrInvalidRequestID.Msgf(f.options.TemplateID, id)); err != nil {
				gologger.Error().Msgf("failed to store flow runtime errors got %v", err)
			}
			return matcherStatus.Load()
		}
		err := req.ExecuteWithResults(f.input, output.InternalEvent(f.options.GetTemplateCtx(f.input.MetaInput).GetAll()), nil, f.getProtoRequestCallback(req, matcherStatus, opts))
		if err != nil {
			index := id
			err = f.allErrs.Set(opts.protoName+":"+index, err)
			if err != nil {
				gologger.Error().Msgf("failed to store flow runtime errors got %v", err)
			}
		}
	}
	return matcherStatus.Load()
}

// getProtoRequestCallback returns a callback that is executed
// after execution of each protocol request
func (f *FlowExecutor) getProtoRequestCallback(req protocols.Request, matcherStatus *atomic.Bool, opts *ProtoOptions) func(result *output.InternalWrappedEvent) {
	return func(result *output.InternalWrappedEvent) {
		if result != nil {
			f.results.CompareAndSwap(false, true)
			f.lastEvent = result
			// export dynamic values from operators (i.e internal:true)
			// add add it to template context
			// this is a conflicting behaviour with iterate-all
			if result.HasOperatorResult() {
				// this is to handle case where there is any operator result (matcher or extractor)
				matcherStatus.CompareAndSwap(false, result.OperatorsResult.Matched)
				if !result.OperatorsResult.Matched && !hasMatchers(req.GetCompiledOperators()) {
					// if matcher status is false . check if template/request contains any matcher at all
					// if it does then we need to set matcher status to true
					matcherStatus.CompareAndSwap(false, true)
				}
				if len(result.OperatorsResult.DynamicValues) > 0 {
					for k, v := range result.OperatorsResult.DynamicValues {
						f.options.GetTemplateCtx(f.input.MetaInput).Set(k, v)
					}
				}
			} else if !result.HasOperatorResult() && !hasOperators(req.GetCompiledOperators()) {
				// this is to handle case where there are no operator result and there was no matcher in operators
				// if matcher status is false . check if template/request contains any matcher at all
				// if it does then we need to set matcher status to true
				matcherStatus.CompareAndSwap(false, true)
			}
		}
	}
}

// registerBuiltInFunctions registers all built in functions for the flow
func (f *FlowExecutor) registerBuiltInFunctions() error {
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
		f.options.GetTemplateCtx(f.input.MetaInput).Set(types.ToString(varName), varValue)
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

	// add a builtin dedupe object
	if err := f.jsVM.Set("Dedupe", func(call goja.ConstructorCall) *goja.Object {
		d := builtin.NewDedupe(f.jsVM)
		obj := call.This
		// register these methods
		_ = obj.Set("Add", d.Add)
		_ = obj.Set("Values", d.Values)
		return nil
	}); err != nil {
		return err
	}

	var m = f.options.GetTemplateCtx(f.input.MetaInput).GetAll()
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
