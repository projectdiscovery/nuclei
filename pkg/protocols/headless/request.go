package headless

import (
	"fmt"
	"maps"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

var _ protocols.Request = &Request{}

const errCouldNotGetHtmlElement = "could not get html element"

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.HeadlessProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	if request.SelfContained {
		url, err := extractBaseURLFromActions(request.Steps)
		if err != nil {
			return err
		}
		input = contextargs.NewWithInput(input.Context(), url)
	}

	if request.options.Browser.UserAgent() == "" {
		request.options.Browser.SetUserAgent(request.compiledUserAgent)
	}

	vars := protocolutils.GenerateVariablesWithContextArgs(input, false)
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	scope := request.options.NewVariablesScope(vars)
	// add templatecontext variables to varMap
	if request.options.HasTemplateCtx(input.MetaInput) {
		request.options.AddTemplateCtxToVariablesScope(input.MetaInput, scope)
	}

	scope.AddData(metadata, optionVars, request.options.Constants)
	evaluation := request.options.Variables.EvaluateWithInteractshScope(scope, request.options.Interactsh)
	variablesMap, interactshURLs := evaluation.Values, evaluation.InteractURLs
	if request.options.HasTemplateCtx(input.MetaInput) {
		vars = generators.MergeMaps(vars, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	vars = generators.MergeMaps(vars, metadata, optionVars, variablesMap, request.options.Constants)

	// check for operator matches by wrapping callback
	var gotmatches atomic.Bool
	var callbackMu sync.Mutex
	wrappedCallback := func(results *output.InternalWrappedEvent) {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		callback(results)
		if results != nil && results.OperatorsResult != nil && results.OperatorsResult.Matched {
			gotmatches.Store(true)
		}
	}
	// verify if fuzz elaboration was requested
	if len(request.Fuzzing) > 0 {
		return request.executeFuzzingRule(input, vars, previous, wrappedCallback)
	}
	timing := newHeadlessTimingTrace(request.options.TemplateID, input.MetaInput.Input)
	if timing != nil {
		defer timing.emit()
	}
	if request.generator != nil {
		if request.Threads > 1 && !protocolstate.IsLowOnMemory() {
			return request.executeConcurrentPayloads(input, vars, interactshURLs, previous, wrappedCallback, &gotmatches, timing)
		}
		iterator := request.generator.NewIterator()
		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}

			if gotmatches.Load() && (request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch) {
				return nil
			}

			renderedValue, err := render.RenderMap(render.MapInput{
				Options:      request.options.GetOptions(),
				Source:       value,
				Data:         vars,
				Values:       generators.MergeMaps(value, vars),
				Interactsh:   request.options.Interactsh,
				InteractURLs: interactshURLs,
			})
			if err != nil {
				return errors.Wrap(err, "could not evaluate payload helper expressions")
			}

			if err := request.executeRequestWithPayloads(input, renderedValue.Values, previous, renderedValue.InteractURLs, wrappedCallback, timing, nil); err != nil {
				return err
			}
		}
	} else {
		value := maps.Clone(vars)
		if err := request.executeRequestWithPayloads(input, value, previous, interactshURLs, wrappedCallback, timing, nil); err != nil {
			return err
		}
	}

	return nil
}

func (request *Request) executeConcurrentPayloads(input *contextargs.Context, vars map[string]interface{}, interactshURLs []string, previous output.InternalEvent, callback protocols.OutputEventCallback, gotmatches *atomic.Bool, timing *headlessTimingTrace) error {
	var workers sync.WaitGroup
	var stateMu, outputMu sync.Mutex
	var firstErr error
	var stop atomic.Bool
	semaphore := make(chan struct{}, request.Threads)
	stopAtFirstMatch := request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch

	iterator := request.generator.NewIterator()
	for {
		value, ok := iterator.Value()
		if !ok || stop.Load() || (stopAtFirstMatch && gotmatches.Load()) {
			break
		}
		renderedValue, err := render.RenderMap(render.MapInput{
			Options:      request.options.GetOptions(),
			Source:       value,
			Data:         vars,
			Values:       generators.MergeMaps(value, vars),
			Interactsh:   request.options.Interactsh,
			InteractURLs: interactshURLs,
		})
		if err != nil {
			stateMu.Lock()
			if firstErr == nil {
				firstErr = errors.Wrap(err, "could not evaluate payload helper expressions")
			}
			stateMu.Unlock()
			break
		}

		select {
		case semaphore <- struct{}{}:
		case <-input.Context().Done():
			workers.Wait()
			return input.Context().Err()
		}
		if stop.Load() || (stopAtFirstMatch && gotmatches.Load()) {
			<-semaphore
			break
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-semaphore }()
			childTiming := timing.child()
			err := request.executeRequestWithPayloads(input, renderedValue.Values, previous, renderedValue.InteractURLs, callback, childTiming, &outputMu)
			stateMu.Lock()
			timing.merge(childTiming)
			if err != nil && firstErr == nil {
				firstErr = err
				stop.Store(true)
			}
			stateMu.Unlock()
		}()
	}
	workers.Wait()
	return firstErr
}

// This function extracts the base URL from actions.
func extractBaseURLFromActions(steps []*engine.Action) (string, error) {
	for _, action := range steps {
		if action.ActionType.ActionType == engine.ActionNavigate {
			navigateURL := action.GetArg("url")
			url, err := urlutil.Parse(navigateURL)
			if err != nil {
				return "", errors.Errorf("could not parse URL '%s': %s", navigateURL, err.Error())
			}
			return fmt.Sprintf("%s://%s", url.Scheme, url.Host), nil
		}
	}
	return "", errors.New("no navigation action found")
}

func (request *Request) executeRequestWithPayloads(input *contextargs.Context, payloads map[string]interface{}, previous output.InternalEvent, interactshURLs []string, callback protocols.OutputEventCallback, timing *headlessTimingTrace, outputMu *sync.Mutex) error {
	if timing != nil {
		timing.attempts++
	}
	pageTimeout := time.Duration(request.options.Options.PageTimeout) * time.Second
	if _, err := url.Parse(input.MetaInput.Input); err != nil {
		if timing != nil {
			timing.errors++
		}
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
	}
	options := &engine.Options{
		Timeout:       pageTimeout,
		DisableCookie: request.DisableCookie,
		Options:       request.options.Options,
	}

	if !options.DisableCookie && input.CookieJar == nil {
		if timing != nil {
			timing.errors++
		}
		return errors.New("cookie reuse enabled but cookie-jar is nil")
	}

	// limited as one request per run of the steps, the unit progress counts
	var rateWaitStarted time.Time
	if timing != nil {
		rateWaitStarted = time.Now()
	}
	rateWaitErr := request.options.RateLimitTakeContext(input.Context(), input.MetaInput.Input)
	if timing != nil {
		timing.rateWait += time.Since(rateWaitStarted)
	}
	if rateWaitErr != nil {
		if timing != nil {
			timing.errors++
		}
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), rateWaitErr)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(rateWaitErr, "could not take rate limit")
	}

	var createStarted time.Time
	if timing != nil {
		createStarted = time.Now()
	}
	instance, err := request.options.Browser.NewInstanceWithContext(input.Context(), pageTimeout)
	if timing != nil {
		timing.contextCreate += time.Since(createStarted)
	}
	if err != nil {
		if timing != nil {
			timing.errors++
		}
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
	}
	var page *engine.Page
	defer func() {
		var cleanupStarted time.Time
		if timing != nil {
			cleanupStarted = time.Now()
		}
		if closeErr := instance.CloseWithPage(page); closeErr != nil {
			gologger.Warning().Msgf("Could not close headless browser instance: %s", closeErr)
		}
		if timing != nil {
			timing.cleanup += time.Since(cleanupStarted)
		}
	}()
	instance.SetInteractsh(request.options.Interactsh)

	timeStart := time.Now()
	out, createdPage, err := instance.Run(input, request.Steps, payloads, options)
	runDuration := time.Since(timeStart)
	if timing != nil {
		if err != nil {
			timing.errors++
			timing.runOther += runDuration
		} else if createdPage != nil {
			timing.recordRun(request.Steps, createdPage.ActionDurations, runDuration)
		} else {
			timing.runOther += runDuration
		}
	}
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, errCouldNotGetHtmlElement)
	}
	page = createdPage

	page.InteractshURLs = append(interactshURLs, page.InteractshURLs...)

	reqLog := instance.GetRequestLog()
	navigatedURL := request.getLastNavigationURLWithLog(reqLog) // also known as matchedURL if there is a match

	request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), nil)
	request.options.Progress.IncrementRequests()
	gologger.Verbose().Msgf("Sent Headless request to %s", navigatedURL)

	reqBuilder := &strings.Builder{}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.DebugResponse {
		gologger.Info().Msgf("[%s] Dumped Headless request for %s", request.options.TemplateID, navigatedURL)

		for _, act := range request.Steps {
			if act.ActionType.ActionType == engine.ActionNavigate {
				value := act.GetArg("url")
				if reqLog[value] != "" {
					_, _ = fmt.Fprintf(reqBuilder, "\tnavigate => %v\n", reqLog[value])
				} else {
					_, _ = fmt.Fprintf(reqBuilder, "%v not found in %v\n", value, reqLog)
				}
			} else {
				actStepStr := act.String()
				_, _ = fmt.Fprintf(reqBuilder, "\t%s\n", actStepStr)
			}
		}
		gologger.Debug().Msg(reqBuilder.String())
	}

	var responseBody string
	html, err := page.Page().Element("html")
	if err == nil {
		responseBody, _ = html.HTML()
	}

	header := out.GetOrDefault("header", "").(string)

	// NOTE(dwisiswant0): `status_code` key should be an integer type.
	// Ref: https://github.com/projectdiscovery/nuclei/pull/5545#discussion_r1721291013
	statusCode := out.GetOrDefault("status_code", "").(string)

	outputEvent := request.responseToDSLMap(responseBody, header, statusCode, reqBuilder.String(), input.MetaInput.Input, navigatedURL, page.DumpHistory())
	addHeadlessDurationFields(outputEvent, page.ActionDurations, runDuration)
	if outputMu != nil {
		outputMu.Lock()
		defer outputMu.Unlock()
	}
	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}

	maps.Copy(outputEvent, out)
	maps.Copy(outputEvent, payloads)

	var event *output.InternalWrappedEvent
	if len(page.InteractshURLs) == 0 {
		event = eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: outputEvent}
		request.options.RegisterInteractshRequest(page.InteractshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}
	if len(page.InteractshURLs) > 0 {
		event.UsesInteractsh = true
	}

	dumpResponse(event, request.options, responseBody, input.MetaInput.Input)
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	if shouldStopAtFirstMatch && event.HasOperatorResult() {
		return types.ErrNoMoreRequests
	}
	return nil
}

func addHeadlessDurationFields(event output.InternalEvent, actionDurations []time.Duration, runDuration time.Duration) {
	if len(actionDurations) == 0 {
		event["duration"] = runDuration.Seconds()
		return
	}
	for i, duration := range actionDurations {
		seconds := duration.Seconds()
		event[fmt.Sprintf("duration_%d", i+1)] = seconds
		event["duration"] = seconds
	}
}

func dumpResponse(event *output.InternalWrappedEvent, requestOptions *protocols.ExecutorOptions, responseBody string, input string) {
	if requestOptions.Options.Debug || requestOptions.Options.DebugResponse || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped Headless response for %s\n\n", requestOptions.TemplateID, input)
		if requestOptions.Options.Debug || requestOptions.Options.DebugResponse {
			resp := responsehighlighter.Highlight(event.OperatorsResult, responseBody, requestOptions.Options.NoColor, false)
			gologger.Debug().Msgf("%s%s", msg, resp)
		}
		if requestOptions.Options.StoreResponse {
			requestOptions.Output.WriteStoreDebugData(input, requestOptions.TemplateID, "headless", fmt.Sprintf("%s%s", msg, responseBody))
		}
	}
}

// executeFuzzingRule executes a fuzzing rule in the template request
func (request *Request) executeFuzzingRule(input *contextargs.Context, payloads map[string]interface{}, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// check for operator matches by wrapping callback
	gotmatches := false
	fuzzRequestCallback := func(gr fuzz.GeneratedRequest) bool {
		if gotmatches && (request.StopAtFirstMatch || request.options.Options.StopAtFirstMatch || request.options.StopAtFirstMatch) {
			return true
		}
		newInput := input.Clone()
		newInput.MetaInput.Input = gr.Request.String()

		if err := request.executeRequestWithPayloads(newInput, gr.DynamicValues, previous, gr.InteractURLs, callback, nil, nil); err != nil {
			return false
		}

		return true
	}

	if _, err := urlutil.Parse(input.MetaInput.Input); err != nil {
		return errors.Wrap(err, "could not parse url")
	}

	baseRequest, err := retryablehttp.NewRequest("GET", input.MetaInput.Input, nil)
	if err != nil {
		return errors.Wrap(err, "could not create base request")
	}

	for _, rule := range request.Fuzzing {
		err := rule.Execute(&fuzz.ExecuteRuleInput{
			Input:       input,
			Callback:    fuzzRequestCallback,
			Values:      payloads,
			BaseRequest: baseRequest,
		})
		if err == types.ErrNoMoreRequests {
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "could not execute rule")
		}
	}
	return nil
}

// getLastNavigationURLWithLog returns last successfully navigated URL
func (request *Request) getLastNavigationURLWithLog(reqLog map[string]string) string {
	for i := len(request.Steps) - 1; i >= 0; i-- {
		if request.Steps[i].ActionType.ActionType == engine.ActionNavigate {
			templateURL := request.Steps[i].GetArg("url")
			if reqLog[templateURL] != "" {
				return reqLog[templateURL]
			}
		}
	}
	return ""
}
