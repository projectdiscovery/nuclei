package flow

import (
	"fmt"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// contains all internal/unexported methods of flow

// requestExecutor executes a protocol/request and returns true if any matcher was found
func (f *FlowExecutor) requestExecutor(runtime *goja.Runtime, reqMap mapsutil.Map[string, protocols.Request], opts *ProtoOptions) bool {
	defer func() {
		// evaluate all variables after execution of each protocol
		variableMap := f.options.Variables.Evaluate(f.options.GetTemplateCtx(f.ctx.Input.MetaInput).GetAll())
		f.options.GetTemplateCtx(f.ctx.Input.MetaInput).Merge(variableMap) // merge all variables into template context

		// to avoid polling update template variables everytime we execute a protocol
		var m map[string]interface{} = f.options.GetTemplateCtx(f.ctx.Input.MetaInput).GetAll()
		_ = runtime.Set("template", m)
	}()
	matcherStatus := &atomic.Bool{} // due to interactsh matcher polling logic this needs to be atomic bool
	// if no id is passed execute all requests in sequence
	if len(opts.reqIDS) == 0 {
		// execution logic for http()/dns() etc
		for index := range f.allProtocols[opts.protoName] {
			req := f.allProtocols[opts.protoName][index]
			// transform input if required
			inputItem := f.ctx.Input.Clone()
			if f.options.InputHelper != nil && f.ctx.Input.MetaInput.Input != "" {
				if inputItem.MetaInput.Input = f.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
					f.ctx.LogError(fmt.Errorf("failed to transform input for protocol %s", req.Type()))
					return false
				}
			}
			err := req.ExecuteWithResults(inputItem, output.InternalEvent(f.options.GetTemplateCtx(f.ctx.Input.MetaInput).GetAll()), output.InternalEvent{}, f.protocolResultCallback(req, matcherStatus, opts))
			if err != nil {
				// save all errors in a map with id as key
				// its less likely that there will be race condition but just in case
				id := req.GetID()
				if id == "" {
					id, _ = reqMap.GetKeyWithValue(req)
				}
				err = f.allErrs.Set(opts.protoName+":"+id, err)
				if err != nil {
					f.ctx.LogError(fmt.Errorf("failed to store flow runtime errors got %v", err))
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
			f.ctx.LogError(fmt.Errorf("[%v] invalid request id '%s' provided", f.options.TemplateID, id))
			// compile error
			if err := f.allErrs.Set(opts.protoName+":"+id, ErrInvalidRequestID.Msgf(f.options.TemplateID, id)); err != nil {
				f.ctx.LogError(fmt.Errorf("failed to store flow runtime errors got %v", err))
			}
			return matcherStatus.Load()
		}
		// transform input if required
		inputItem := f.ctx.Input.Clone()
		if f.options.InputHelper != nil && f.ctx.Input.MetaInput.Input != "" {
			if inputItem.MetaInput.Input = f.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
				f.ctx.LogError(fmt.Errorf("failed to transform input for protocol %s", req.Type()))
				return false
			}
		}
		err := req.ExecuteWithResults(inputItem, output.InternalEvent(f.options.GetTemplateCtx(f.ctx.Input.MetaInput).GetAll()), output.InternalEvent{}, f.protocolResultCallback(req, matcherStatus, opts))
		if err != nil {
			index := id
			err = f.allErrs.Set(opts.protoName+":"+index, err)
			if err != nil {
				f.ctx.LogError(fmt.Errorf("failed to store flow runtime errors got %v", err))
			}
		}
	}
	return matcherStatus.Load()
}

// protocolResultCallback returns a callback that is executed
// after execution of each protocol request
func (f *FlowExecutor) protocolResultCallback(req protocols.Request, matcherStatus *atomic.Bool, _ *ProtoOptions) func(result *output.InternalWrappedEvent) {
	return func(result *output.InternalWrappedEvent) {
		if result != nil {
			// Note: flow specific implicit behaviours should be handled here
			// before logging the event
			f.ctx.LogEvent(result)
			// export dynamic values from operators (i.e internal:true)
			// add add it to template context
			// this is a conflicting behaviour with iterate-all
			if result.HasOperatorResult() {
				f.results.CompareAndSwap(false, true)
				// this is to handle case where there is any operator result (matcher or extractor)
				matcherStatus.CompareAndSwap(false, result.OperatorsResult.Matched)
				if !result.OperatorsResult.Matched && !hasMatchers(req.GetCompiledOperators()) {
					// if matcher status is false . check if template/request contains any matcher at all
					// if it does then we need to set matcher status to true
					matcherStatus.CompareAndSwap(false, true)
				}
				if len(result.OperatorsResult.DynamicValues) > 0 {
					for k, v := range result.OperatorsResult.DynamicValues {
						// if length of v is 1 then remove slice and convert it to single value
						if len(v) == 1 {
							// add it to flatten keys list so it will be flattened to a string later
							f.flattenKeys = append(f.flattenKeys, k)
							// flatten and convert it to string
							f.options.GetTemplateCtx(f.ctx.Input.MetaInput).Set(k, v[0])
						} else {
							// keep it as slice
							f.options.GetTemplateCtx(f.ctx.Input.MetaInput).Set(k, v)
						}
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
