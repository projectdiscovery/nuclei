package headless

import (
	"context"
	"strings"

	// 	"github.com/projectdiscovery/gologger"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/raw"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/utils"
	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/utils"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	// 	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	// 	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	// urlutil "github.com/projectdiscovery/utils/url"
)

// ErrEvalExpression
var (
	ErrEvalExpression = errorutil.NewWithTag("expr", "could not evaluate helper expressions")
	ErrUnresolvedVars = errorutil.NewWithFmt("unresolved variables `%v` found in request")
)

// generatedRequest is a single generated request wrapped for a template request
type generatedRequest struct {
	original             *Request
	meta                 map[string]interface{}
	request              *retryablehttp.Request
	dynamicValues        map[string]interface{}
	interactshURLs       []string
	customCancelFunction context.CancelFunc
}

func (g *generatedRequest) URL() string {
	if g.request != nil {
		return g.request.URL.String()
	}
	return ""
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	if r.payloadIterator != nil {
		return len(r.request.Payloads) * r.payloadIterator.Remaining()
	}
	return len(r.request.Payloads)
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(ctx context.Context, input *contextargs.Context, reqData string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
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

	// defaultreqvars are vars generated from request/input ex: {{baseURL}}, {{Host}} etc
	// contextargs generate extra vars that may/may not be available always (ex: "ip")
	defaultReqVars := protocolutils.GenerateVariables(parsed, false, contextargs.GenerateVariables(input))
	// optionvars are vars passed from CLI or env variables
	optionVars := generators.BuildPayloadFromOptions(r.request.options.Options)

	variablesMap, interactURLs := r.options.Variables.EvaluateWithInteractsh(generators.MergeMaps(defaultReqVars, optionVars), r.options.Interactsh)
	if len(interactURLs) > 0 {
		r.interactshURLs = append(r.interactshURLs, interactURLs...)
	}
	// allVars contains all variables from all sources
	allVars := generators.MergeMaps(dynamicValues, defaultReqVars, optionVars, variablesMap)

	// Evaluate payload variables
	// eg: payload variables can be username: jon.doe@{{Hostname}}
	for payloadName, payloadValue := range payloads {
		payloads[payloadName], err = expressions.Evaluate(types.ToString(payloadValue), allVars)
		if err != nil {
			return nil, ErrEvalExpression.Wrap(err).WithTag("http")
		}
	}
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
		return nil, ErrEvalExpression.Wrap(err).WithTag("headless")
	}

	reqURL, err := urlutil.ParseURL(reqData, true)
	if err != nil {
		return nil, errorutil.NewWithTag("headless", "failed to parse url %v while creating headless request", reqData)
	}
	// while merging parameters first preference is given to target params
	finalparams := parsed.Params
	finalparams.Merge(reqURL.Params)
	reqURL.Params = finalparams
	return r.generateHttpRequest(ctx, reqURL, finalVars, payloads)
}

// generateHttpRequest generates http request from request data from template and variables
// finalVars = contains all variables including generator and protocol specific variables
// generatorValues = contains variables used in fuzzing or other generator specific values
func (r *requestGenerator) generateHttpRequest(ctx context.Context, urlx *urlutil.URL, finalVars, generatorValues map[string]interface{}) (*generatedRequest, error) {
	v, _ := r.request.Payloads["redirect"]
	method, err := expressions.Evaluate(v.(string), finalVars)
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

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *retryablehttp.Request, values map[string]interface{}) (*retryablehttp.Request, error) {
	// Set the header values requested
	for header, value := range r.request. {
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
