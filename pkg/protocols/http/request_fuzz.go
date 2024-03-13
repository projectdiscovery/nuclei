package http

// === Fuzzing Documentation (Scoped to this File) =====
// -> request.executeFuzzingRule   [iterates over payloads(+requests) and executes]
//	-> request.executePayloadUsingRules [executes single payload on all rules (if more than 1)]
//		-> request.executeGeneratedFuzzingRequest [execute final generated fuzzing request and get result]

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// executeFuzzingRule executes fuzzing request for a URL
// TODO:
// 1. use SPMHandler and rewrite stop at first match logic here
// 2. use scanContext instead of contextargs.Context
func (request *Request) executeFuzzingRule(input *contextargs.Context, _ output.InternalEvent, callback protocols.OutputEventCallback) error {
	// methdology:
	// to check applicablity of rule, we first try to execute it with one value
	// if it is applicable, we execute all requests
	// if it is not applicable, we log and fail silently

	// check if target should be fuzzed or not
	if !request.ShouldFuzzTarget(input) {
		urlx, _ := input.MetaInput.URL()
		if urlx != nil {
			gologger.Verbose().Msgf("[%s] fuzz: target(%s) not applicable for fuzzing\n", request.options.TemplateID, urlx.String())
		} else {
			gologger.Verbose().Msgf("[%s] fuzz: target(%s) not applicable for fuzzing\n", request.options.TemplateID, input.MetaInput.Input)
		}
		return nil
	}

	// Iterate through all requests for template and queue them for fuzzing
	generator := request.newGenerator(true)

	// this will generate next value along with request it is meant to be used with
	currRequest, payloads, result := generator.nextValue()
	if !result && input.MetaInput.ReqResp == nil {
		// this case is only true if input is not a full http request
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
			if errors.Is(err, errStopExecution) {
				return err
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
		if errors.Is(err, errStopExecution) {
			return err
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
		return errors.Wrap(err, "could not execute rule")
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

// ShouldFuzzTarget checks if given target should be fuzzed or not using `filter` field in template
func (request *Request) ShouldFuzzTarget(input *contextargs.Context) bool {
	if len(request.FuzzingFilter) == 0 {
		return true
	}
	status := []bool{}
	for index, filter := range request.FuzzingFilter {
		isMatch, _ := request.Match(request.filterDataMap(input), filter)
		status = append(status, isMatch)
		if request.options.Options.MatcherStatus {
			gologger.Debug().Msgf("[%s] [%s] Filter => %s : %v", input.MetaInput.Target(), request.options.TemplateID, operators.GetMatcherName(filter, index), isMatch)
		}
	}
	if len(status) == 0 {
		return true
	}
	var matched bool
	if request.fuzzingFilterCondition == matchers.ANDCondition {
		matched = operators.EvalBoolSlice(status, true)
	} else {
		matched = operators.EvalBoolSlice(status, false)
	}
	if request.options.Options.MatcherStatus {
		gologger.Debug().Msgf("[%s] [%s] Final Filter Status =>  %v", input.MetaInput.Target(), request.options.TemplateID, matched)
	}
	return matched
}

// input data map returns map[string]interface{} from input
func (request *Request) filterDataMap(input *contextargs.Context) map[string]interface{} {
	m := make(map[string]interface{})
	parsed, err := input.MetaInput.URL()
	if err != nil {
		m["host"] = input.MetaInput.Input
		return m
	}
	m = protocolutils.GenerateVariables(parsed, true, m)
	for k, v := range m {
		m[strings.ToLower(k)] = v
	}
	m["path"] = parsed.Path // override existing
	m["query"] = parsed.RawQuery
	// add request data like headers, body etc
	if input.MetaInput.ReqResp != nil && input.MetaInput.ReqResp.Request != nil {
		req := input.MetaInput.ReqResp.Request
		m["method"] = req.Method
		m["body"] = req.Body

		sb := &strings.Builder{}
		req.Headers.Iterate(func(k, v string) bool {
			k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
			if strings.EqualFold(k, "Cookie") {
				m["cookie"] = v
			}
			if strings.EqualFold(k, "User_Agent") {
				m["user_agent"] = v
			}
			if strings.EqualFold(k, "content_type") {
				m["content_type"] = v
			}
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			return true
		})
		m["header"] = sb.String()
	}

	// dump if svd is enabled
	if request.options.Options.ShowVarDump {
		gologger.Debug().Msgf("Fuzz Filter Variables: \n%s\n", vardump.DumpVariables(m))
	}
	return m
}
