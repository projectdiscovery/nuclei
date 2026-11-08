package http

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/useragent"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/race"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/raw"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	ReqURLPatternKey = "req_url_pattern"
)

// ErrEvalExpression
type errorTemplate struct {
	format string
}

func (e errorTemplate) Wrap(err error) wrapperError {
	return wrapperError{template: e, err: err}
}

func (e errorTemplate) Msgf(args ...interface{}) error {
	return errkit.Newf(e.format, args...)
}

type wrapperError struct {
	template errorTemplate
	err      error
}

func (w wrapperError) WithTag(tag string) error {
	return errkit.Wrap(w.err, w.template.format)
}

func (w wrapperError) Msgf(format string, args ...interface{}) error {
	return errkit.Wrapf(w.err, format, args...)
}

func (w wrapperError) Error() string {
	return errkit.Wrap(w.err, w.template.format).Error()
}

// ErrEvalExpression
var (
	ErrEvalExpression = errorTemplate{"could not evaluate helper expressions"}
	ErrUnresolvedVars = errorTemplate{"unresolved variables `%v` found in request"}
)

// generatedRequest is a single generated request wrapped for a template request
type generatedRequest struct {
	original             *Request
	rawRequest           *raw.Request
	meta                 map[string]interface{}
	pipelinedClient      *rawhttp.PipelineClient
	request              *retryablehttp.Request
	dynamicValues        map[string]interface{}
	interactshURLs       []string
	customCancelFunction context.CancelFunc
	// sendTimeout starts after the body budget admits the request.
	sendTimeout  time.Duration
	bodyReserved bool
	// requestURLPattern tracks unmodified request url pattern without values ( it is used for constant vuln_hash)
	// ex: {{BaseURL}}/api/exp?param={{randstr}}
	requestURLPattern string

	fuzzGeneratedRequest fuzz.GeneratedRequest
}

// setReqURLPattern sets the url request pattern for the generated request
func (gr *generatedRequest) setReqURLPattern(reqURLPattern string) {
	if idx := strings.IndexByte(reqURLPattern, '\n'); idx >= 0 {
		reqURLPattern = strings.TrimSpace(reqURLPattern[:idx])
		// this is raw request (if it has 3 parts after strings.Fields then its valid only use 2nd part)
		parts := strings.Fields(reqURLPattern)
		if len(parts) >= 3 {
			// remove first and last and use all in between
			parts = parts[1 : len(parts)-1]
			reqURLPattern = strings.Join(parts, " ")
		}
	} else {
		reqURLPattern = strings.TrimSpace(reqURLPattern)
	}

	// now urlRequestPattern is generated replace preprocessor values with actual placeholders
	// that were used (these are called generated 'constants' and contains {{}} in var name)
	for k, v := range gr.original.options.Constants {
		if strings.HasPrefix(k, "{{") && strings.HasSuffix(k, "}}") {
			// this takes care of all preprocessors ( currently we have randstr and its variations)
			reqURLPattern = strings.ReplaceAll(reqURLPattern, fmt.Sprint(v), k)
		}
	}
	gr.requestURLPattern = reqURLPattern
}

// ApplyAuth applies the auth provider to the generated request
func (g *generatedRequest) ApplyAuth(provider authprovider.AuthProvider) {
	if provider == nil {
		return
	}
	if g.request != nil {
		authStrategies := provider.LookupURLX(g.request.URL)
		for _, strategy := range authStrategies {
			strategy.ApplyOnRR(g.request)
		}
	}
	if g.rawRequest != nil {
		parsed, err := urlutil.ParseAbsoluteURL(g.rawRequest.FullURL, true)
		if err != nil {
			gologger.Warning().Msgf("[authprovider] Could not parse URL %s: %s\n", g.rawRequest.FullURL, err)
			return
		}
		authStrategies := provider.LookupURLX(parsed)
		// here we need to apply it custom because we don't have a standard/official
		// rawhttp request format ( which we probably should have )
		for _, strategy := range authStrategies {
			g.rawRequest.ApplyAuthStrategy(strategy)
		}
	}
}

func (g *generatedRequest) URL() string {
	if g.request != nil {
		return g.request.String()
	}
	if g.rawRequest != nil {
		return g.rawRequest.FullURL
	}
	return ""
}

// Make creates a http request for the provided input.
// It returns ErrNoMoreRequests as error when all the requests have been exhausted.
func (r *requestGenerator) Make(ctx context.Context, input *contextargs.Context, reqData string, payloads, dynamicValues map[string]interface{}) (gr *generatedRequest, err error) {
	origReqData := reqData
	r.interactshURLs = nil
	defer func() {
		if gr != nil {
			gr.setReqURLPattern(origReqData)
		}
	}()
	// value of `reqData` depends on the type of request specified in template
	// 1. If request is raw request =  reqData contains raw request (i.e http request dump)
	// 2. If request is Normal ( simply put not a raw request) (Ex: with placeholders `path`) = reqData contains relative path

	isRawRequest := len(r.request.Raw) > 0
	for payloadName, payloadValue := range payloads {
		payloads[payloadName] = types.ToStringNSlice(payloadValue)
	}

	if r.request.SelfContained {
		return r.makeSelfContainedRequest(ctx, input, reqData, payloads, dynamicValues)
	}

	// Parse target url
	parsed, err := urlutil.ParseAbsoluteURL(input.MetaInput.Input, false)
	if err != nil {
		return nil, err
	}

	// Non-Raw Requests ex `{{BaseURL}}/somepath` may or maynot have slash after variable and the same is the case for
	// target url to avoid inconsistencies extra slash if exists has to removed from default variables
	hasTrailingSlash := false
	if !isRawRequest {
		// if path contains port ex: {{BaseURL}}:8080 use port specified in reqData
		parsed, reqData = httputil.UpdateURLPortFromPayload(parsed, reqData)
		hasTrailingSlash = httputil.HasTrailingSlash(reqData)
	}

	// defaultreqvars are vars generated from request/input ex: {{baseURL}}, {{Host}} etc
	// contextargs generate extra vars that may/may not be available always (ex: "ip")
	defaultReqVars := protocolutils.GenerateVariables(parsed, hasTrailingSlash, contextargs.GenerateVariables(input))
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(r.request.options.Options)

	scope := r.options.NewVariablesScope()
	r.options.AddTemplateCtxToVariablesScope(input.MetaInput, scope)
	scope.AddData(dynamicValues, defaultReqVars, optionVars, r.options.Constants)
	evaluation := r.options.Variables.EvaluateWithInteractshScope(scope, r.options.Interactsh)

	variablesMap, interactURLs := evaluation.Values, evaluation.InteractURLs
	if len(interactURLs) > 0 {
		r.interactshURLs = append(r.interactshURLs, interactURLs...)
	}

	// allVars contains all variables from all sources
	allVars := make(map[string]interface{})
	if r.request.options.HasTemplateCtx(input.MetaInput) {
		allVars = generators.MergeMaps(r.request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}

	allVars = generators.MergeMaps(allVars, dynamicValues, defaultReqVars, optionVars, variablesMap, r.options.Constants)

	// Evaluate payload variables
	// eg: payload variables can be username: jon.doe@{{Hostname}}
	for payloadName, payloadValue := range payloads {
		payloads[payloadName], err = r.renderText(types.ToString(payloadValue), allVars)
		if err != nil {
			return nil, errkit.Wrap(err, "could not evaluate helper expressions")
		}
	}
	// finalVars contains allVars and any generator/fuzzing specific payloads
	// payloads used in generator should be given the most preference
	finalVars := generators.MergeMaps(allVars, payloads)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("HTTP Protocol request variables: %s\n", vardump.DumpVariables(finalVars))
	}

	// Note: If possible any changes to current logic (i.e evaluate -> then parse URL)
	// should be avoided since it is dependent on `urlutil` core logic

	// Evaluate (replace) variable with final values
	reqData, err = r.renderText(reqData, finalVars)
	if err != nil {
		return nil, errkit.Wrap(err, "could not evaluate helper expressions")
	}

	if isRawRequest {
		return r.generateRawRequest(ctx, reqData, parsed, finalVars, payloads)
	}

	reqURL, err := urlutil.ParseAbsoluteURL(reqData, true)
	if err != nil {
		return nil, errkit.Newf("failed to parse url %v while creating http request", reqData)
	}

	// while merging parameters first preference is given to target params
	finalparams := parsed.Params
	finalparams.Merge(reqURL.Params.Encode())
	reqURL.Params = finalparams

	return r.generateHttpRequest(ctx, reqURL, finalVars, payloads)
}

// validateSelfContainedHost validates a self-contained request's destination
// host against the execution network policy.
func (r *requestGenerator) validateSelfContainedHost(host string) error {
	if host == "" {
		return nil
	}
	executionId := r.request.options.Options.ExecutionId
	if !protocolstate.IsHostAllowed(executionId, host) {
		return errkit.Newf("self-contained request host %s is blocked by network policy", host)
	}
	return nil
}

// selfContained templates do not need/use target data and all values i.e {{Hostname}} , {{BaseURL}} etc are already available
// in template . makeSelfContainedRequest parses and creates variables map and then creates corresponding http request or raw request
func (r *requestGenerator) makeSelfContainedRequest(ctx context.Context, input *contextargs.Context, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	if r.request.isRaw() {
		return r.makeSelfContainedRawRequest(ctx, input, data, payloads, dynamicValues)
	}

	values, _, err := r.selfContainedValues(input, payloads, dynamicValues, nil)
	if err != nil {
		return nil, err
	}

	data, err = r.renderText(data, values)
	if err != nil {
		return nil, errkit.Wrap(err, "could not evaluate helper expressions")
	}
	if err := expressions.ContainsUnresolvedVariables(data); err != nil && !r.request.SkipVariablesCheck {
		// early exit: if there are any unresolved variables in `path` after evaluation
		// then return early since this will definitely fail
		return nil, errkit.Newf("unresolved variables `%v` found in request", data)
	}

	urlx, err := urlutil.ParseURL(data, true)
	if err != nil {
		return nil, errkit.Wrapf(err, "failed to parse %v in self contained request", data)
	}
	// validate the self-chosen destination host against the network policy.
	if err := r.validateSelfContainedHost(urlx.Hostname()); err != nil {
		return nil, err
	}
	return r.generateHttpRequest(ctx, urlx, values, payloads)
}

// makeSelfContainedRawRequest makes a self-contained raw request. Its request
// line names the URL, and that URL provides variables such as {{Hostname}} to
// the rest of the request. Each part of the template text is rendered once,
// so inserted values such as response data are sent unchanged:
//
//  1. Render the request line and check its host against the network policy.
//  2. Evaluate again the template variables and payloads whose template text
//     names URL variables. The others keep their values, so a random value
//     is the same in the request line and in the rest of the request.
//  3. Render the annotations and the rest of the request.
func (r *requestGenerator) makeSelfContainedRawRequest(ctx context.Context, input *contextargs.Context, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	annotations, requestLine, rest, err := splitRequestLine(data)
	if err != nil {
		return nil, err
	}

	// Payloads are rendered in place, so keep their template text for step 2.
	payloadText := generators.CopyMap(payloads)

	values, authored, err := r.selfContainedValues(input, payloads, dynamicValues, nil)
	if err != nil {
		return nil, err
	}

	requestLine, err = r.renderText(requestLine, values)
	if err != nil {
		return nil, errkit.Wrap(err, "could not evaluate helper expressions")
	}

	// Parse the line that raw.ParseRawRequest will read, even if a value
	// added a line break.
	firstLine, _, _ := strings.Cut(requestLine, "\n")

	parsed, err := r.requestLineURL(firstLine)
	if err != nil {
		return nil, err
	}

	// URL variables only fill in names that have no other value.
	fixed := make(map[string]interface{})

	for name, value := range protocolutils.GenerateVariables(parsed, false, nil) {
		if _, ok := values[name]; !ok {
			fixed[name] = value
		}
	}

	stale := r.staleValues(authored, payloadText, fixed)
	if len(stale) == 0 {
		values = generators.MergeMaps(fixed, values)
	} else {
		// Keep every other value, and evaluate the stale template variables
		// and payloads again from their template text.
		for name, value := range values {
			if _, ok := stale[name]; !ok {
				fixed[name] = value
			}
		}

		for name := range stale {
			if text, ok := payloadText[name]; ok {
				payloads[name] = text
			}
		}

		values, _, err = r.selfContainedValues(input, payloads, dynamicValues, fixed)
		if err != nil {
			return nil, err
		}
	}

	annotations, err = r.renderText(annotations, values)
	if err != nil {
		return nil, errkit.Wrap(err, "could not evaluate helper expressions")
	}

	rest, err = r.renderText(rest, values)
	if err != nil {
		return nil, errkit.Wrap(err, "could not evaluate helper expressions")
	}

	data = annotations + requestLine + rest

	// A value with a line break must not change which line is the request
	// line, or the request would go to a host that was not checked.
	if _, line, _, err := splitRequestLine(data); err != nil || line != firstLine {
		return nil, errkit.New("malformed request supplied: a value changed the request line")
	}

	return r.generateRawRequest(ctx, data, parsed, values, payloads)
}

// staleValues returns the names of the authored values whose template text
// names one of urlValues, directly or through another stale value. It reads
// template text only, so data inserted into a value cannot mark it stale.
// Variables are checked in evaluation order, then payloads, which are
// rendered after the variables.
func (r *requestGenerator) staleValues(authored, payloadText, urlValues map[string]interface{}) map[string]struct{} {
	stale := make(map[string]struct{})
	names := generators.CopyMap(urlValues)

	mark := func(name string, text interface{}) {
		if _, ok := authored[name]; !ok {
			return
		}

		if expressions.ReferencesVariables(types.ToString(text), names) {
			stale[name] = struct{}{}
			names[name] = nil
		}
	}

	r.request.options.Variables.ForEach(mark)

	for name, text := range payloadText {
		mark(name, text)
	}

	return stale
}

// requestLineURL returns the URL named by a rendered raw request line after
// checking its host against the network policy.
func (r *requestGenerator) requestLineURL(line string) (*urlutil.URL, error) {
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request supplied")
	}

	if err := expressions.ContainsUnresolvedVariables(parts[1]); err != nil && !r.request.SkipVariablesCheck {
		return nil, errkit.Newf("unresolved variables `%v` found in request", parts[1])
	}

	parsed, err := urlutil.ParseURL(parts[1], true)
	if err != nil {
		return nil, fmt.Errorf("could not parse request URL: %w", err)
	}
	// self-contained requests choose their own destination URL, so validate
	// that host against the network policy.
	if err := r.validateSelfContainedHost(parsed.Hostname()); err != nil {
		return nil, err
	}

	return parsed, nil
}

// selfContainedValues evaluates the template variables and renders the
// payloads of a self-contained request, and returns the values to render the
// request with. Payloads are rendered in place. Values in fixed are data:
// they fill in names that have no other value, and a template variable or
// payload with the same name keeps that value instead of being evaluated.
// It also returns the values it produced from template text, that is the
// evaluated template variables and the rendered payloads.
func (r *requestGenerator) selfContainedValues(input *contextargs.Context, payloads, dynamicValues, fixed map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	optionValues := generators.BuildPayloadFromOptions(r.request.options.Options)
	values := generators.MergeMaps(fixed, optionValues)

	if r.request.options.HasTemplateCtx(input.MetaInput) {
		values = generators.MergeMaps(values, r.request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	values = generators.MergeMaps(values, dynamicValues, payloads)
	// adds all variables from `variables` section in template
	scope := r.request.options.NewVariablesScope(optionValues)
	r.request.options.AddTemplateCtxToVariablesScope(input.MetaInput, scope)
	scope.AddData(dynamicValues, payloads, r.options.Constants, fixed)
	evaluation := r.request.options.Variables.EvaluateWithInteractshScope(scope, r.request.options.Interactsh)

	variablesMap, interactURLs := evaluation.Values, evaluation.InteractURLs
	if len(interactURLs) > 0 {
		r.interactshURLs = append(r.interactshURLs, interactURLs...)
	}

	values = generators.MergeMaps(variablesMap, values)
	signerVars := GetDefaultSignerVars(r.request.Signature.Value)

	// this will ensure that default signer variables are overwritten by other variables
	values = generators.MergeMaps(signerVars, values, r.options.Constants)

	// The evaluation owns TemplateValues, so add the rendered payloads to it.
	authored := evaluation.TemplateValues

	for payloadName, payloadValue := range payloads {
		if _, ok := fixed[payloadName]; ok {
			continue
		}

		renderedPayload, err := r.renderText(types.ToString(payloadValue), values)
		if err != nil {
			return nil, nil, errkit.Wrap(err, "could not evaluate payload helper expressions")
		}

		payloads[payloadName] = renderedPayload
		authored[payloadName] = renderedPayload
	}

	// priority of variables is as follows (from low to high) for self contained templates
	// default signer vars < variables < cli vars < dynamic values < payload < constants
	return generators.MergeMaps(values, payloads, r.options.Constants), authored, nil
}

// splitRequestLine splits raw request template text at its request line, the
// first line that is not an annotation. It returns the annotation lines, the
// request line without its line break, and the remaining text starting with
// that line break. The three parts concatenate back to raw.
func splitRequestLine(raw string) (annotations, requestLine, rest string, err error) {
	start := 0

	for {
		line, _, found := strings.Cut(raw[start:], "\n")
		if !found {
			return "", "", "", errkit.New("could not read request: no request line found")
		}

		if !strings.HasPrefix(line, "@") {
			return raw[:start], line, raw[start+len(line):], nil
		}

		start += len(line) + 1
	}
}

// generateHttpRequest generates http request from request data from template and variables
// finalVars = contains all variables including generator and protocol specific variables
// generatorValues = contains variables used in fuzzing or other generator specific values
func (r *requestGenerator) generateHttpRequest(ctx context.Context, urlx *urlutil.URL, finalVars, generatorValues map[string]interface{}) (*generatedRequest, error) {
	method, err := r.renderText(r.request.Method.String(), finalVars)
	if err != nil {
		return nil, errkit.Wrap(err, "failed to evaluate while generating http request")
	}

	// Build a request on the specified URL
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, method, urlx, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, finalVars)
	if err != nil {
		return nil, err
	}

	return &generatedRequest{request: request, meta: generatorValues, original: r.request, dynamicValues: finalVars, interactshURLs: r.interactshURLs}, nil
}

// generateRawRequest generates Raw Request from request data from template and variables
// finalVars = contains all variables including generator and protocol specific variables
// generatorValues = contains variables used in fuzzing or other generator specific values
func (r *requestGenerator) generateRawRequest(ctx context.Context, rawRequest string, baseURL *urlutil.URL, finalVars, generatorValues map[string]interface{}) (*generatedRequest, error) {
	var rawRequestData *raw.Request
	var err error

	if r.request.SelfContained {
		// in self contained requests baseURL is extracted from raw request itself
		rawRequestData, err = raw.ParseRawRequest(rawRequest, r.request.Unsafe)
	} else {
		rawRequestData, err = raw.Parse(rawRequest, baseURL, r.request.Unsafe, r.request.DisablePathAutomerge)
	}
	if err != nil {
		return nil, errkit.Wrap(err, "failed to parse raw request")
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		annotationURL := rawRequestData.FullURL
		if annotationURL == "" && baseURL != nil {
			cloned := baseURL.Clone()
			cloned.Params.IncludeEquals = true
			cloned.Path = ""
			_ = cloned.MergePath(rawRequestData.Path, true)
			annotationURL = cloned.String()
			rawRequestData.FullURL = annotationURL
		}

		var annotationOverrides annotationOverrides
		if annotationURL != "" {
			annotationRequest, reqErr := retryablehttp.NewRequestWithContext(ctx, rawRequestData.Method, annotationURL, nil)
			if reqErr == nil {
				if hostHeader, ok := rawRequestData.Headers["Host"]; ok {
					annotationRequest.Host = hostHeader
				}

				annotationOverrides, _ = r.request.parseAnnotations(rawRequest, annotationRequest)
				if annotationOverrides.err != nil {
					return nil, errkit.Wrap(annotationOverrides.err, "failed to apply raw request annotations")
				}
				if annotationOverrides.request != nil && annotationOverrides.request.URL != nil {
					rawRequestData.FullURL = annotationOverrides.request.String()
				}
			}
		}

		if len(r.options.Options.CustomHeaders) > 0 {
			customHeaders := make([]string, 0, len(r.options.Options.CustomHeaders))
			for _, header := range r.options.Options.CustomHeaders {
				customHeaders = append(customHeaders, evaluateCustomHeaderExpressions(r.options.TemplateID, header, finalVars))
			}
			_ = rawRequestData.TryFillCustomHeaders(customHeaders)
		}

		if rawRequestData.Data != "" && !stringsutil.EqualFoldAny(rawRequestData.Method, http.MethodHead, http.MethodGet) && rawRequestData.Headers["Transfer-Encoding"] != "chunked" {
			rawRequestData.Headers["Content-Length"] = strconv.Itoa(len(rawRequestData.Data))
		}

		unsafeReq := &generatedRequest{rawRequest: rawRequestData, meta: generatorValues, original: r.request, interactshURLs: r.interactshURLs}
		if annotationOverrides.cancelFunc != nil {
			unsafeReq.customCancelFunction = annotationOverrides.cancelFunc
		}

		if len(annotationOverrides.interactshURLs) > 0 {
			unsafeReq.interactshURLs = append(unsafeReq.interactshURLs, annotationOverrides.interactshURLs...)
		}

		return unsafeReq, nil
	}
	urlx, err := urlutil.ParseAbsoluteURL(rawRequestData.FullURL, true)
	if err != nil {
		return nil, errkit.Wrapf(err, "failed to create request with url %v got %v", rawRequestData.FullURL, err)
	}
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, rawRequestData.Method, urlx, nil)
	if err != nil {
		return nil, err
	}
	// Set the body here rather than through retryablehttp, which copies it
	// several times over.
	httpbody.SetString(req, rawRequestData.Data)

	// force transfer encoding if conditions are met
	if len(rawRequestData.Data) > 0 && req.Header.Get("Transfer-Encoding") != "chunked" && !stringsutil.EqualFoldAny(rawRequestData.Method, http.MethodGet, http.MethodHead) {
		req.ContentLength = int64(len(rawRequestData.Data))
	}

	// override the body with a new one that will be used to read the request body in parallel threads
	// for race condition testing
	if r.request.Threads > 0 && r.request.Race {
		req.Body = race.NewOpenGateWithTimeout(req.Body, time.Duration(2)*time.Second)
	}

	for key, value := range rawRequestData.Headers {
		if key == "" {
			continue
		}
		req.Header[key] = []string{value}
		if key == "Host" {
			req.Host = value
		}
	}

	request, err := r.fillRequest(req, finalVars)
	if err != nil {
		return nil, err
	}

	generatedRequest := &generatedRequest{
		request:        request,
		meta:           generatorValues,
		original:       r.request,
		dynamicValues:  finalVars,
		interactshURLs: r.interactshURLs,
	}

	if reqWithOverrides, hasAnnotations := r.request.parseAnnotations(rawRequest, req); hasAnnotations {
		if reqWithOverrides.err != nil {
			return nil, errkit.Wrap(reqWithOverrides.err, "failed to apply raw request annotations")
		}
		generatedRequest.request = reqWithOverrides.request
		generatedRequest.customCancelFunction = reqWithOverrides.cancelFunc
		generatedRequest.interactshURLs = append(generatedRequest.interactshURLs, reqWithOverrides.interactshURLs...)
	}

	return generatedRequest, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *retryablehttp.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	// Set the header values requested
	for header, value := range r.request.Headers {
		value, err := r.renderText(value, values)
		if err != nil {
			return nil, errkit.Wrap(err, "failed to evaluate while adding headers to request")
		}

		req.Header[header] = []string{value}
		if header == "Host" {
			req.Host = value
		}
	}

	// Respect the connection reuse policy from the smart analyzer.
	switch r.request.connectionReusePolicy {
	case ReuseUnsafe:
		// Force connection close for requests that must not reuse connections
		if req.Header.Get("Connection") == "" {
			req.Header.Set("Connection", "close")
		}
		req.Close = true
	case ReuseSafe:
		// Allow connection pooling: drop any explicit close header
		if strings.EqualFold(req.Header.Get("Connection"), "close") {
			req.Header.Del("Connection")
		}
	default:
		// Defer to the connection-level keep-alive decision: per-host clients
		// keep connections alive unless a template explicitly disabled it.
		if r.request.connConfiguration != nil && r.request.connConfiguration.Connection != nil &&
			r.request.connConfiguration.Connection.DisableKeepAlive && req.Header.Get("Connection") == "" {
			req.Close = true
		}
	}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body, err := r.renderText(r.request.Body, values)
		if err != nil {
			return nil, errkit.Wrap(err, "could not evaluate helper expressions")
		}

		httpbody.SetString(req, body)
	}

	if !r.request.Unsafe {
		userAgent := useragent.PickRandom()
		httputil.SetHeader(req, "User-Agent", userAgent.Raw)
	}

	// Only set these headers on non-raw requests
	if len(r.request.Raw) == 0 && !r.request.Unsafe {
		httputil.SetHeader(req, "Accept", "*/*")
		httputil.SetHeader(req, "Accept-Language", "en")
	}

	if !LeaveDefaultPorts {
		switch {
		case req.Scheme == "http" && strings.HasSuffix(req.Host, ":80"):
			req.Host = strings.TrimSuffix(req.Host, ":80")
		case req.Scheme == "https" && strings.HasSuffix(req.Host, ":443"):
			req.Host = strings.TrimSuffix(req.Host, ":443")
		}
	}

	if r.request.DigestAuthUsername != "" {
		req.Auth = &retryablehttp.Auth{
			Type:     retryablehttp.DigestAuth,
			Username: r.request.DigestAuthUsername,
			Password: r.request.DigestAuthPassword,
		}
	}

	return req, nil
}

func (r *requestGenerator) renderText(text string, values map[string]interface{}) (string, error) {
	result, err := render.Render(render.Input{
		Options:      r.options.GetOptions(),
		Text:         text,
		Values:       values,
		Interactsh:   r.options.Interactsh,
		InteractURLs: r.interactshURLs,
	})
	if err != nil {
		return "", err
	}

	r.interactshURLs = result.InteractURLs

	return result.Text, nil
}
