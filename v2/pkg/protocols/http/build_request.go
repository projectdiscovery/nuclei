package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/race"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	readerutil "github.com/projectdiscovery/utils/reader"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// ErrEvalExpression
var ErrEvalExpression = errorutil.NewWithTag("expr", "could not evaluate helper expressions")

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
}

func (g *generatedRequest) URL() string {
	if g.request != nil {
		return g.request.URL.String()
	}
	if g.rawRequest != nil {
		return g.rawRequest.FullURL
	}
	return ""
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	if r.payloadIterator != nil {
		return len(r.request.Raw) * r.payloadIterator.Remaining()
	}
	return len(r.request.Path)
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(ctx context.Context, input *contextargs.Context, reqData string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// value of `reqData` depends on the type of request specified in template
	// 1. If request is raw request =  reqData contains raw request (i.e http request dump)
	// 2. If request is Normal ( simply put not a raw request) (Ex: with placeholders `path`) = reqData contains relative path
	if r.request.SelfContained {
		return r.makeSelfContainedRequest(ctx, reqData, payloads, dynamicValues)
	}
	isRawRequest := len(r.request.Raw) > 0
	// replace interactsh variables with actual interactsh urls
	if r.options.Interactsh != nil {
		reqData, r.interactshURLs = r.options.Interactsh.Replace(reqData, []string{})
		for payloadName, payloadValue := range payloads {
			payloads[payloadName], r.interactshURLs = r.options.Interactsh.Replace(types.ToString(payloadValue), r.interactshURLs)
		}
	} else {
		for payloadName, payloadValue := range payloads {
			payloads[payloadName] = types.ToString(payloadValue)
		}
	}

	// Parse target url
	parsed, err := urlutil.Parse(input.MetaInput.Input)
	if err != nil {
		return nil, err
	}

	// Non-Raw Requests ex `{{BaseURL}}/somepath` may or maynot have slash after variable and the same is the case for
	// target url to avoid inconsistencies extra slash if exists has to removed from default variables
	hasTrailingSlash := false
	if !isRawRequest {
		// if path contains port ex: {{BaseURL}}:8080 use port specified in reqData
		parsed, reqData = utils.UpdateURLPortFromPayload(parsed, reqData)
		hasTrailingSlash = utils.HasTrailingSlash(reqData)
	}

	// defaultreqvars are vars generated from request/input ex: {{baseURL}}, {{Host}} etc
	// contextargs generate extra vars that may/may not be available always (ex: "ip")
	defaultReqVars := utils.GenerateVariablesWithURL(parsed, hasTrailingSlash, contextargs.GenerateVariables(input))
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(r.request.options.Options)
	// allVars contains all variables from all sources
	allVars := generators.MergeMaps(dynamicValues, defaultReqVars, optionVars)

	// finalVars contains allVars and any generator/fuzzing specific payloads
	// payloads used in generator should be given the most preference
	finalVars := generators.MergeMaps(allVars, payloads)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Final Protocol request variables: \n%s\n", vardump.DumpVariables(finalVars))
	}

	// Note: If possible any changes to current logic (i.e evaluate -> then parse URL)
	// should be avoided since it is dependent on `urlutil` core logic

	// Evaluate (replace) variable with final values
	reqData, err = expressions.Evaluate(reqData, finalVars)
	if err != nil {
		return nil, ErrEvalExpression.Wrap(err).WithTag("http")
	}

	if isRawRequest {
		return r.generateRawRequest(ctx, reqData, parsed, finalVars, payloads)
	}

	reqURL, err := urlutil.ParseURL(reqData, true)
	if err != nil {
		return nil, errorutil.NewWithTag("http", "failed to parse url %v while creating http request", reqData)
	}
	// while merging parameters first preference is given to target params
	finalparams := parsed.Params
	finalparams.Merge(reqURL.Params)
	reqURL.Params = finalparams
	return r.generateHttpRequest(ctx, reqURL, finalVars, payloads)
}

// selfContained templates do not need/use target data and all values i.e {{Hostname}} , {{BaseURL}} etc are already available
// in template . makeSelfContainedRequest parses and creates variables map and then creates corresponding http request or raw request
func (r *requestGenerator) makeSelfContainedRequest(ctx context.Context, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	isRawRequest := r.request.isRaw()

	// If the request is a raw request, get the URL from the request
	// header and use it to make the request.
	if isRawRequest {
		// Get the hostname from the URL section to build the request.
		reader := bufio.NewReader(strings.NewReader(data))
	read_line:
		s, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("could not read request: %w", err)
		}
		// ignore all annotations
		if stringsutil.HasPrefixAny(s, "@") {
			goto read_line
		}

		parts := strings.Split(s, " ")
		if len(parts) < 3 {
			return nil, fmt.Errorf("malformed request supplied")
		}

		// Note: Here the order of payloads matter since payloads passed through file ex: -V "test=numbers.txt"
		// are stored in payloads and options vars should not override payloads in any case
		values := generators.MergeMaps(
			generators.BuildPayloadFromOptions(r.request.options.Options),
			payloads,
		)

		parts[1] = replacer.Replace(parts[1], values)
		if len(dynamicValues) > 0 {
			parts[1] = replacer.Replace(parts[1], dynamicValues)
		}

		// the url might contain placeholders with ignore list
		if ignoreList := GetVariablesNamesSkipList(r.request.Signature.Value); ignoreList != nil {
			if err := expressions.ContainsVariablesWithIgnoreList(ignoreList, parts[1]); err != nil {
				return nil, err
			}
		} else if err := expressions.ContainsUnresolvedVariables(parts[1]); err != nil { // the url might contain placeholders
			return nil, err
		}

		parsed, err := urlutil.ParseURL(parts[1], true)
		if err != nil {
			return nil, fmt.Errorf("could not parse request URL: %w", err)
		}
		values = generators.MergeMaps(
			generators.MergeMaps(dynamicValues, utils.GenerateVariablesWithURL(parsed, false, nil)),
			values,
		)
		// Evaluate (replace) variable with final values
		data, err = expressions.Evaluate(data, values)
		if err != nil {
			return nil, ErrEvalExpression.Wrap(err).WithTag("self-contained", "raw")
		}
		return r.generateRawRequest(ctx, data, parsed, values, payloads)
	}
	values := generators.MergeMaps(
		generators.BuildPayloadFromOptions(r.request.options.Options),
		dynamicValues,
		payloads, // payloads should override other variables in case of duplicate vars
	)
	// Evaluate (replace) variable with final values
	data, err := expressions.Evaluate(data, values)
	if err != nil {
		return nil, ErrEvalExpression.Wrap(err).WithTag("self-contained")
	}
	urlx, err := urlutil.ParseURL(data, true)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to parse %v in self contained request", data).WithTag("self-contained")
	}
	return r.generateHttpRequest(ctx, urlx, values, payloads)
}

// generateHttpRequest generates http request from request data from template and variables
// finalVars = contains all variables including generator and protocol specific variables
// generatorValues = contains variables used in fuzzing or other generator specific values
func (r *requestGenerator) generateHttpRequest(ctx context.Context, urlx *urlutil.URL, finalVars, generatorValues map[string]interface{}) (*generatedRequest, error) {
	method, err := expressions.Evaluate(r.request.Method.String(), finalVars)
	if err != nil {
		return nil, ErrEvalExpression.Wrap(err).Msgf("failed to evaluate while generating http request")
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

// generateRawRequest generates Raw Request from from request data from template and variables
// finalVars = contains all variables including generator and protocol specific variables
// generatorValues = contains variables used in fuzzing or other generator specific values
func (r *requestGenerator) generateRawRequest(ctx context.Context, rawRequest string, baseURL *urlutil.URL, finalVars, generatorValues map[string]interface{}) (*generatedRequest, error) {
	rawRequestData, err := raw.Parse(rawRequest, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		if len(r.options.Options.CustomHeaders) > 0 {
			_ = rawRequestData.TryFillCustomHeaders(r.options.Options.CustomHeaders)
		}
		unsafeReq := &generatedRequest{rawRequest: rawRequestData, meta: generatorValues, original: r.request, interactshURLs: r.interactshURLs}
		return unsafeReq, nil
	}

	var body io.ReadCloser
	body = io.NopCloser(strings.NewReader(rawRequestData.Data))
	if r.request.Race {
		// More or less this ensures that all requests hit the endpoint at the same approximated time
		// Todo: sync internally upon writing latest request byte
		body = race.NewOpenGateWithTimeout(body, time.Duration(2)*time.Second)
	}
	urlx, err := urlutil.ParseURL(rawRequestData.FullURL, true)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to create request with url %v got %v", rawRequestData.FullURL, err).WithTag("raw")
	}
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, rawRequestData.Method, urlx, body)
	if err != nil {
		return nil, err
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
		if r.options.Interactsh != nil {
			value, r.interactshURLs = r.options.Interactsh.Replace(value, r.interactshURLs)
		}
		value, err := expressions.Evaluate(value, values)
		if err != nil {
			return nil, ErrEvalExpression.Wrap(err).Msgf("failed to evaluate while adding headers to request")
		}
		req.Header[header] = []string{value}
		if header == "Host" {
			req.Host = value
		}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	if r.request.Threads <= 0 && req.Header.Get("Connection") == "" {
		req.Close = true
	}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body := r.request.Body
		if r.options.Interactsh != nil {
			body, r.interactshURLs = r.options.Interactsh.Replace(r.request.Body, r.interactshURLs)
		}
		body, err := expressions.Evaluate(body, values)
		if err != nil {
			return nil, ErrEvalExpression.Wrap(err)
		}
		bodyReader, err := readerutil.NewReusableReadCloser([]byte(body))
		if err != nil {
			return nil, errors.Wrap(err, "failed to create reusable reader for request body")
		}
		req.Body = bodyReader
	}
	if !r.request.Unsafe {
		utils.SetHeader(req, "User-Agent", uarand.GetRandom())
	}

	// Only set these headers on non-raw requests
	if len(r.request.Raw) == 0 && !r.request.Unsafe {
		utils.SetHeader(req, "Accept", "*/*")
		utils.SetHeader(req, "Accept-Language", "en")
	}

	if !LeaveDefaultPorts {
		switch {
		case req.URL.Scheme == "http" && strings.HasSuffix(req.Host, ":80"):
			req.Host = strings.TrimSuffix(req.Host, ":80")
		case req.URL.Scheme == "https" && strings.HasSuffix(req.Host, ":443"):
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
