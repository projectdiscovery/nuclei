package http

// === Fuzzing Documentation (Scoped to this File) =====
// -> request.executeFuzzingRule   [iterates over payloads(+requests) and executes]
//	-> request.executePayloadUsingRules [executes single payload on all rules (if more than 1)]
//		-> request.executeGeneratedFuzzingRequest [execute final generated fuzzing request and get result]

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	urlutil "github.com/projectdiscovery/utils/url"
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

	if input.MetaInput.Input == "" && input.MetaInput.ReqResp == nil {
		return errors.New("empty input provided for fuzzing")
	}

	// ==== fuzzing when full HTTP request is provided =====

	if input.MetaInput.ReqResp != nil {
		baseRequest, err := input.MetaInput.ReqResp.BuildRequest()
		if err != nil {
			return errors.Wrap(err, "fuzz: could not build request obtained from target file")
		}
		request.addHeadersToRequest(baseRequest)
		input.MetaInput.Input = baseRequest.URL.String()
		// execute with one value first to checks its applicability
		err = request.executeAllFuzzingRules(input, previous, baseRequest, callback)
		if err != nil {
			// in case of any error, return it
			if fuzz.IsErrRuleNotApplicable(err) {
				// log and fail silently
				gologger.Verbose().Msgf("[%s] fuzz: %s\n", request.options.TemplateID, err)
				return nil
			}
			if errors.Is(err, ErrMissingVars) {
				return err
			}
			gologger.Verbose().Msgf("[%s] fuzz: payload request execution failed : %s\n", request.options.TemplateID, err)
		}
		return nil
	}

	// ==== fuzzing when only URL is provided =====

	// we need to use this url instead of input
	inputx := input.Clone()
	parsed, err := urlutil.ParseAbsoluteURL(input.MetaInput.Input, true)
	if err != nil {
		return errors.Wrap(err, "fuzz: could not parse input url")
	}
	baseRequest, err := retryablehttp.NewRequestFromURL(http.MethodGet, parsed, nil)
	if err != nil {
		return errors.Wrap(err, "fuzz: could not build request from url")
	}
	userAgent := useragent.PickRandom()
	baseRequest.Header.Set("User-Agent", userAgent.Raw)
	request.addHeadersToRequest(baseRequest)

	// execute with one value first to checks its applicability
	err = request.executeAllFuzzingRules(inputx, previous, baseRequest, callback)
	if err != nil {
		// in case of any error, return it
		if fuzz.IsErrRuleNotApplicable(err) {
			// log and fail silently
			gologger.Verbose().Msgf("[%s] fuzz: rule not applicable : %s\n", request.options.TemplateID, err)
			return nil
		}
		if errors.Is(err, ErrMissingVars) {
			return err
		}
		gologger.Verbose().Msgf("[%s] fuzz: payload request execution failed : %s\n", request.options.TemplateID, err)
	}
	return nil
}

func (request *Request) addHeadersToRequest(baseRequest *retryablehttp.Request) {
	for k, v := range request.Headers {
		baseRequest.Header.Set(k, v)
	}
}

// executeAllFuzzingRules executes all fuzzing rules defined in template for a given base request
func (request *Request) executeAllFuzzingRules(input *contextargs.Context, values map[string]interface{}, baseRequest *retryablehttp.Request, callback protocols.OutputEventCallback) error {
	applicable := false
	values = generators.MergeMaps(request.filterDataMap(input), values)
	for _, rule := range request.Fuzzing {
		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		input := &fuzz.ExecuteRuleInput{
			Input:             input,
			DisplayFuzzPoints: request.options.Options.DisplayFuzzPoints,
			Callback: func(gr fuzz.GeneratedRequest) bool {
				select {
				case <-input.Context().Done():
					return false
				default:
				}

				// TODO: replace this after scanContext Refactor
				return request.executeGeneratedFuzzingRequest(gr, input, callback)
			},
			Values:      values,
			BaseRequest: baseRequest.Clone(context.TODO()),
		}
		if request.Analyzer != nil {
			analyzer := analyzers.GetAnalyzer(request.Analyzer.Name)
			input.ApplyPayloadInitialTransformation = analyzer.ApplyInitialTransformation
			input.AnalyzerParams = request.Analyzer.Parameters
		}
		err := rule.Execute(input)
		if err == nil {
			applicable = true
			continue
		}
		if fuzz.IsErrRuleNotApplicable(err) {
			gologger.Verbose().Msgf("[%s] fuzz: rule not applicable : %s\n", request.options.TemplateID, err)
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
	if request.options.HostErrorsCache != nil && request.options.HostErrorsCache.Check(request.options.ProtocolType.String(), input) {
		return false
	}
	request.options.RateLimitTake()
	req := &generatedRequest{
		request:              gr.Request,
		dynamicValues:        gr.DynamicValues,
		interactshURLs:       gr.InteractURLs,
		original:             request,
		fuzzGeneratedRequest: gr,
	}
	var gotMatches bool
	requestErr := request.executeRequest(input, req, gr.DynamicValues, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
		for _, result := range event.Results {
			result.IsFuzzingResult = true
			result.FuzzingMethod = gr.Request.Method
			result.FuzzingParameter = gr.Parameter
			result.FuzzingPosition = gr.Component.Name()
		}

		setInteractshCallback := false
		if hasInteractMarkers && hasInteractMatchers && request.options.Interactsh != nil {
			requestData := &interactsh.RequestData{
				MakeResultFunc: request.MakeResultEvent,
				Event:          event,
				Operators:      request.CompiledOperators,
				MatchFunc:      request.Match,
				ExtractFunc:    request.Extract,
				Parameter:      gr.Parameter,
				Request:        gr.Request,
			}
			setInteractshCallback = true
			request.options.Interactsh.RequestEvent(gr.InteractURLs, requestData)
			gotMatches = request.options.Interactsh.AlreadyMatched(requestData)
		} else {
			callback(event)
		}
		// Add the extracts to the dynamic values if any.
		if event.OperatorsResult != nil {
			gotMatches = event.OperatorsResult.Matched
		}
		if request.options.FuzzParamsFrequency != nil && !setInteractshCallback {
			if !gotMatches {
				request.options.FuzzParamsFrequency.MarkParameter(gr.Parameter, gr.Request.URL.String(), request.options.TemplateID)
			} else {
				request.options.FuzzParamsFrequency.UnmarkParameter(gr.Parameter, gr.Request.URL.String(), request.options.TemplateID)
			}
		}
	}, 0)
	// If a variable is unresolved, skip all further requests
	if errors.Is(requestErr, ErrMissingVars) {
		return false
	}
	if requestErr != nil {
		gologger.Verbose().Msgf("[%s] Error occurred in request: %s\n", request.options.TemplateID, requestErr)
	}
	if request.options.HostErrorsCache != nil {
		request.options.HostErrorsCache.MarkFailedOrRemove(request.options.ProtocolType.String(), input, requestErr)
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
	if len(request.FuzzPreCondition) == 0 {
		return true
	}
	status := []bool{}
	for index, filter := range request.FuzzPreCondition {
		dataMap := request.filterDataMap(input)
		// dump if svd is enabled
		if request.options.Options.ShowVarDump {
			gologger.Debug().Msgf("Fuzz Filter Variables: \n%s\n", vardump.DumpVariables(dataMap))
		}
		isMatch, _ := request.Match(dataMap, filter)
		status = append(status, isMatch)
		if request.options.Options.MatcherStatus {
			gologger.Debug().Msgf("[%s] [%s] Filter => %s : %v", input.MetaInput.Target(), request.options.TemplateID, operators.GetMatcherName(filter, index), isMatch)
		}
	}
	if len(status) == 0 {
		return true
	}
	var matched bool
	if request.fuzzPreConditionOperator == matchers.ANDCondition {
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
	} else {
		// add default method value
		m["method"] = http.MethodGet
	}
	return m
}
