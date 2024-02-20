package http

// === Fuzzing Documentation (Scoped to this File) =====
// -> request.executeFuzzingRule   [iterates over payloads(+requests) and executes]
//	-> request.executePayloadUsingRules [executes single payload on all rules (if more than 1)]
//		-> request.executeGeneratedFuzzingRequest [execute final generated fuzzing request and get result]

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// executeFuzzingRule executes fuzzing request for a URL
// TODO:
// 1. use SPMHandler and rewrite stop at first match logic here
// 2. use scanContext instead of contextargs.Context
func (request *Request) executeFuzzingRule(input *contextargs.Context, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// methdology:
	// to check applicablity of rule, we first try to execute it with one value
	// if it is applicable, we execute all requests
	// if it is not applicable, we log and fail silently

	// Iterate through all requests for template and queue them for fuzzing
	generator := request.newGenerator(true)

	// this will generate next value along with request it is meant to be used with
	currRequest, payloads, result := generator.nextValue()
	if !result {
		return fmt.Errorf("no values to generate requests")
	}

	// if it is a full http request obtained from target file
	if input.MetaInput.ReqResp != nil {
		// Note: in case of full http request, we only need to build it once
		// and then reuse it for all requests and completely abandon the request
		// returned by generator
		_ = currRequest
		generated, err := input.MetaInput.ReqResp.BuildRequest()
		if err != nil {
			return errors.Wrap(err, "fuzz: could not build request obtained from target file")
		}
		input.MetaInput.Input = generated.URL.String()
		// execute with one value first to checks its applicability
		err = request.executePayloadUsingRules(input, payloads, generated, callback)
		if err != nil {
			// in case of any error, return it
			if fuzz.IsErrRuleNotApplicable(err) {
				// log and fail silently
				gologger.Verbose().Msgf("[%s] fuzz: %s\n", request.options.TemplateID, err)
				return nil
			}
			gologger.Verbose().Msgf("[%s] fuzz: inital payload request execution failed : %s\n", request.options.TemplateID, err)
		}

		// if it is applicable, execute all requests
		for {
			_, payloads, result := generator.nextValue()
			if !result {
				break
			}
			err = request.executePayloadUsingRules(input, payloads, generated, callback)
			if err != nil {
				// continue to next request since this is payload specific
				gologger.Verbose().Msgf("[%s] fuzz: payload request execution failed : %s\n", request.options.TemplateID, err)
				continue
			}
		}
		return nil
	}

	// ==== fuzzing when only URL is provided =====

	generated, err := generator.Make(context.Background(), input, currRequest, payloads, nil)
	if err != nil {
		return errors.Wrap(err, "fuzz: could not build request from url")
	}
	// we need to use this url instead of input
	inputx := input.Clone()
	inputx.MetaInput.Input = generated.request.URL.String()
	// execute with one value first to checks its applicability
	err = request.executePayloadUsingRules(inputx, generated.dynamicValues, generated.request, callback)
	if err != nil {
		// in case of any error, return it
		if fuzz.IsErrRuleNotApplicable(err) {
			// log and fail silently
			gologger.Verbose().Msgf("[%s] fuzz: rule not applicable : %s\n", request.options.TemplateID, err)
			return nil
		}
		gologger.Verbose().Msgf("[%s] fuzz: inital payload request execution failed : %s\n", request.options.TemplateID, err)
	}

	// continue to next request since this is payload specific
	for {
		currRequest, payloads, result = generator.nextValue()
		if !result {
			break
		}
		generated, err := generator.Make(context.Background(), input, currRequest, payloads, nil)
		if err != nil {
			return errors.Wrap(err, "fuzz: could not build request from url")
		}
		// we need to use this url instead of input
		inputx := input.Clone()
		inputx.MetaInput.Input = generated.request.URL.String()
		// execute with one value first to checks its applicability
		err = request.executePayloadUsingRules(inputx, generated.dynamicValues, generated.request, callback)
		if err != nil {
			gologger.Verbose().Msgf("[%s] fuzz: payload request execution failed : %s\n", request.options.TemplateID, err)
			continue
		}
	}
	return nil
}

// executePayloadUsingRules executes a payload using rules with given payload i.e values
func (request *Request) executePayloadUsingRules(input *contextargs.Context, values map[string]interface{}, baseRequest *retryablehttp.Request, callback protocols.OutputEventCallback) error {
	applicable := false
	for _, rule := range request.Fuzzing {
		err := rule.Execute(&fuzz.ExecuteRuleInput{
			Input: input,
			Callback: func(gr fuzz.GeneratedRequest) bool {
				// TODO: replace this after scanContext Refactor
				return request.executeGeneratedFuzzingRequest(gr, input, callback)
			},
			Values:      values,
			BaseRequest: baseRequest,
		})
		if err == nil {
			applicable = true
			continue
		}
		if fuzz.IsErrRuleNotApplicable(err) {
			continue
		}
		if err == types.ErrNoMoreRequests {
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "could not execute rule")
		}
	}

	if !applicable {
		return fuzz.ErrRuleNotApplicable.Msgf(fmt.Sprintf("no rule was applicable for this request: %v", input.MetaInput.Input))
	}
	return nil
}

// executeGeneratedFuzzingRequest executes a generated fuzzing request after building it using rules and payloads
func (request *Request) executeGeneratedFuzzingRequest(gr fuzz.GeneratedRequest, input *contextargs.Context, callback protocols.OutputEventCallback) bool {
	hasInteractMatchers := interactsh.HasMatchers(request.CompiledOperators)
	hasInteractMarkers := len(gr.InteractURLs) > 0
	if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.Check(input.MetaInput.Input) {
		return false
	}
	request.options.RateLimiter.Take()
	req := &generatedRequest{
		request:        gr.Request,
		dynamicValues:  gr.DynamicValues,
		interactshURLs: gr.InteractURLs,
		original:       request,
	}
	var gotMatches bool
	requestErr := request.executeRequest(input, req, gr.DynamicValues, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
		if hasInteractMarkers && hasInteractMatchers && request.options.Interactsh != nil {
			requestData := &interactsh.RequestData{
				MakeResultFunc: request.MakeResultEvent,
				Event:          event,
				Operators:      request.CompiledOperators,
				MatchFunc:      request.Match,
				ExtractFunc:    request.Extract,
			}
			request.options.Interactsh.RequestEvent(gr.InteractURLs, requestData)
			gotMatches = request.options.Interactsh.AlreadyMatched(requestData)
		} else {
			callback(event)
		}
		// Add the extracts to the dynamic values if any.
		if event.OperatorsResult != nil {
			gotMatches = event.OperatorsResult.Matched
		}
	}, 0)
	// If a variable is unresolved, skip all further requests
	if errors.Is(requestErr, errStopExecution) {
		return false
	}
	if requestErr != nil {
		if request.options.HostErrorsCache != nil {
			request.options.HostErrorsCache.MarkFailed(input.MetaInput.Input, requestErr)
		}
		gologger.Verbose().Msgf("[%s] Error occurred in request: %s\n", request.options.TemplateID, requestErr)
	}
	request.options.Progress.IncrementRequests()

	// If this was a match, and we want to stop at first match, skip all further requests.
	shouldStopAtFirstMatch := request.options.Options.StopAtFirstMatch || request.StopAtFirstMatch
	if shouldStopAtFirstMatch && gotMatches {
		return false
	}
	return true
}
