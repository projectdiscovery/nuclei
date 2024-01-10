package fuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"encoding/json"
	"net/url"
	"strconv"

	"github.com/tidwall/sjson"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	urlutil "github.com/projectdiscovery/utils/url"
)

// executePartRule executes part rules based on type
func (rule *Rule) executePartRule(input *ExecuteRuleInput, payload string) error {
	switch rule.partType {
	case queryPartType:
		return rule.executeQueryPartRule(input, payload)
	case headersPartType:
		return rule.executeHeadersPartRule(input, payload)
	case bodyPartType:
		return rule.executeBodyPartRule(input, payload)
	case allPartType:
		return rule.executeAllPartRule(input, payload)
	}
	return nil
}

// executeHeadersPartRule executes headers part rules
func (rule *Rule) executeHeadersPartRule(input *ExecuteRuleInput, payload string) error {
	// clone the request to avoid modifying the original
	originalRequest := input.BaseRequest
	req := originalRequest.Clone(context.TODO())
	// Also clone headers
	headers := req.Header.Clone()

	for key, values := range originalRequest.Header {
		cloned := sliceutil.Clone(values)
		for i, value := range values {
			if !rule.matchKeyOrValue(key, value) {
				continue
			}
			var evaluated string
			evaluated, input.InteractURLs = rule.executeEvaluate(input, key, value, payload, input.InteractURLs)
			cloned[i] = evaluated

			if rule.modeType == singleModeType {
				headers[key] = cloned
				if err := rule.buildHeadersInput(input, headers, input.InteractURLs); err != nil && err != io.EOF {
					gologger.Error().Msgf("Could not build request for headers part rule %v: %s\n", rule, err)
					return err
				}
				cloned[i] = value // change back to previous value for headers
			}
		}
		headers[key] = cloned
	}

	if rule.modeType == multipleModeType {
		if err := rule.buildHeadersInput(input, headers, input.InteractURLs); err != nil {
			return err
		}
	}
	return nil
}

// executeQueryPartRule executes query part rules
func (rule *Rule) executeQueryPartRule(input *ExecuteRuleInput, payload string) error {
	var err error
	requestURL := input.BaseRequest.URL

	// for unknown reasons, param contain duplicate value
	// only consider the last value of a param values slice
	requestURL.Params.Iterate(func(key string, values []string) bool {
		requestURL.Params.Update(key, values[len(values)-1:]) // only keep the last value of duplicate parameter values
		return true
	})

	origRequestURL := requestURL.Clone()
	// clone the params to avoid modifying the original
	temp := origRequestURL.Params.Clone()

	origRequestURL.Params.Iterate(func(key string, values []string) bool {
		cloned := sliceutil.Clone(values)
		for i, value := range values { // range values[len(values)-1:] to only consider the last value of a duplicate query param
			if !rule.matchKeyOrValue(key, value) {
				continue
			}
			var evaluated string
			evaluated, input.InteractURLs = rule.executeEvaluate(input, key, value, payload, input.InteractURLs)
			cloned[i] = evaluated

			if rule.modeType == singleModeType {
				temp.Update(key, cloned)
				requestURL.Params = temp
				if qerr := rule.buildQueryInput(input, requestURL, input.InteractURLs); qerr != nil {
					err = qerr
					return false
				}
				cloned[i] = value // change back to previous value for temp
			}
		}
		temp.Update(key, cloned)
		return true
	})

	if rule.modeType == multipleModeType {
		requestURL.Params = temp
		if err := rule.buildQueryInput(input, requestURL, input.InteractURLs); err != nil {
			return err
		}
	}

	return err
}

// buildHeadersInput returns created request for a Headers Input
func (rule *Rule) buildHeadersInput(input *ExecuteRuleInput, headers http.Header, interactURLs []string) error {
	var req *retryablehttp.Request
	if input.BaseRequest == nil {
		return errors.New("Base request cannot be nil when fuzzing headers")
	} else {
		req = input.BaseRequest.Clone(context.TODO())
		req.Header = headers
		// update host of request and not URL
		// URL.Host is used to dial the connection
		req.Request.Host = req.Header.Get("Host")
	}
	request := GeneratedRequest{
		Request:       req,
		InteractURLs:  interactURLs,
		DynamicValues: input.Values,
	}
	if !input.Callback(request) {
		return io.EOF
	}
	return nil
}

// buildQueryInput returns created request for a Query Input
func (rule *Rule) buildQueryInput(input *ExecuteRuleInput, parsed *urlutil.URL, interactURLs []string) error {
	var req *retryablehttp.Request
	var err error
	if input.BaseRequest == nil {
		req, err = retryablehttp.NewRequestFromURL(http.MethodGet, parsed, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", uarand.GetRandom())
	} else {
		req = input.BaseRequest.Clone(context.TODO())
		req.SetURL(parsed)
	}
	request := GeneratedRequest{
		Request:       req,
		InteractURLs:  interactURLs,
		DynamicValues: input.Values,
	}
	if !input.Callback(request) {
		return types.ErrNoMoreRequests
	}
	return nil
}

// executeEvaluate executes evaluation of payload on a key and value and
// returns completed values to be replaced and processed
// for fuzzing.
func (rule *Rule) executeEvaluate(input *ExecuteRuleInput, key, value, payload string, interactshURLs []string) (string, []string) {
	// TODO: Handle errors
	values := generators.MergeMaps(input.Values, map[string]interface{}{
		"value": value,
	})
	firstpass, _ := expressions.Evaluate(payload, values)
	interactData, interactshURLs := rule.options.Interactsh.Replace(firstpass, interactshURLs)
	evaluated, _ := expressions.Evaluate(interactData, values)
	replaced := rule.executeReplaceRule(input, value, evaluated)
	return replaced, interactshURLs
}

// executeReplaceRule executes replacement for a key and value
func (rule *Rule) executeReplaceRule(input *ExecuteRuleInput, value, replacement string) string {
	var builder strings.Builder
	if rule.ruleType == prefixRuleType || rule.ruleType == postfixRuleType {
		builder.Grow(len(value) + len(replacement))
	}
	var returnValue string

	switch rule.ruleType {
	case prefixRuleType:
		builder.WriteString(replacement)
		builder.WriteString(value)
		returnValue = builder.String()
	case postfixRuleType:
		builder.WriteString(value)
		builder.WriteString(replacement)
		returnValue = builder.String()
	case infixRuleType:
		if len(value) <= 1 {
			builder.WriteString(value)
			builder.WriteString(replacement)
			returnValue = builder.String()
		} else {
			middleIndex := len(value) / 2
			builder.WriteString(value[:middleIndex])
			builder.WriteString(replacement)
			builder.WriteString(value[middleIndex:])
			returnValue = builder.String()
		}
	case replaceRuleType:
		returnValue = replacement
	}
	return returnValue
}

// executeBodyPartRule executes body part rules
func (rule *Rule) executeBodyPartRule(input *ExecuteRuleInput, payload string) error {
	// clone the request to avoid modifying the original
	originalRequest := input.BaseRequest
	req := originalRequest.Clone(context.TODO())
	contentType := req.Header.Get("Content-Type")

	switch {
	case strings.Contains(req.Path, "/graphql"):
		return rule.fuzzGraphQLBody(input, payload)
	case strings.Contains(contentType, "x-www-form-urlencoded"):
		return rule.fuzzFormBody(input, payload)
	case strings.Contains(contentType, "json"):
		return rule.fuzzJSONBody(input, payload)
	default:
		return rule.fuzzFormBody(input, payload)
	}
}

// returns created request for a Body Input
func (rule *Rule) buildBodyInput(input *ExecuteRuleInput, body string) error {
	var req *retryablehttp.Request
	var err error
	if input.BaseRequest == nil {
		return errors.New("Base request cannot be nil when fuzzing body")
	} else {
		req = input.BaseRequest.Clone(context.TODO())
		req.Request.Body = io.NopCloser(strings.NewReader(body))
		req.Request.ContentLength = int64(len(body))
		req.Request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	request := GeneratedRequest{
		Request:       req,
		InteractURLs:  input.InteractURLs,
		DynamicValues: input.Values,
	}
	if !input.Callback(request) {
		return types.ErrNoMoreRequests
	}
	return err
}

// fuzz all parts sequentially
func (rule *Rule) executeAllPartRule(input *ExecuteRuleInput, payload string) error {
	err := rule.executeQueryPartRule(input, payload)
	if err != nil {
		return err
	}
	err = rule.executeHeadersPartRule(input, payload)
	if err != nil {
		return err
	}
	err = rule.executeBodyPartRule(input, payload)
	if err != nil {
		return err
	}
	return err
}

// fuzzFormBody fuzzes URL encoded form body
func (rule *Rule) fuzzFormBody(input *ExecuteRuleInput, payload string) error {
	var err error
	bodyBytes, _ := io.ReadAll(input.BaseRequest.Body)
	form, err := url.ParseQuery(string(bodyBytes))

	for key, values := range form {
		cloned := sliceutil.Clone(values)
		for i, value := range values {
			var evaluated string
			evaluated, input.InteractURLs = rule.executeEvaluate(input, key, value, payload, input.InteractURLs)
			cloned[i] = evaluated

			if rule.modeType == singleModeType {
				form[key] = []string{evaluated}
				if err := rule.buildBodyInput(input, form.Encode()); err != nil && err != io.EOF {
					return err
				}
				form[key] = []string{value}
			}
		}
		if rule.modeType == multipleModeType {
			form[key] = cloned
		}
	}

	if rule.modeType == multipleModeType {
		if err := rule.buildBodyInput(input, form.Encode()); err != nil {
			return err
		}
	}
	return err
}

// fuzz JSON body based on the mode type
func (rule *Rule) fuzzJSONBody(input *ExecuteRuleInput, payload string) error {
	bodyBytes, err := io.ReadAll(input.BaseRequest.Body)
	if err != nil {
		return err
	}

	var modifiedJson string
	var jsonData interface{}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return err
	}

	flattenedJson := flattenJSON("$", jsonData)

	// fuzz individual postions based on the mode type
	singleFuzz := rule.modeType == singleModeType
	clonedJson := cloneJSON(jsonData)

	for jsonpath, val := range flattenedJson {
		switch v := val.(type) {
		case string:
			if singleFuzz == true {
				fuzzedValue, interactURLs := rule.executeEvaluate(input, "", v, payload, input.InteractURLs)
				input.InteractURLs = interactURLs
				clonedJsonBytes, _ := json.Marshal(clonedJson)
				strClonedJson := string(clonedJsonBytes)
				modifiedJson, _ = sjson.Set(strClonedJson, jsonpath[2:], fuzzedValue) // Remove leading '$.'
				err = rule.buildBodyInput(input, modifiedJson)
			} else {
				fuzzedValue, interactURLs := rule.executeEvaluate(input, "", v, payload, input.InteractURLs)
				input.InteractURLs = interactURLs
				if modifiedJson == "" {
					clonedJsonBytes, _ := json.Marshal(clonedJson)
					modifiedJson = string(clonedJsonBytes)
				}
				modifiedJson, _ = sjson.Set(modifiedJson, jsonpath[2:], fuzzedValue) // Remove leading '$.'
			}
		default:
			continue // ignore non-string values
		}
	}

	if singleFuzz == false {
		err = rule.buildBodyInput(input, modifiedJson)
	}

	return err
}

// fuzzGraphQLBody fuzzes GraphQL body (application/graphql and in-line values (without "variables") are not yet supported)
func (rule *Rule) fuzzGraphQLBody(input *ExecuteRuleInput, payload string) error {
	var err error
	bodyBytes, err := io.ReadAll(input.BaseRequest.Body)

	var graphQLData map[string]interface{}
	err = json.Unmarshal(bodyBytes, &graphQLData)

	variables, _ := graphQLData["variables"].(map[string]interface{})

	for k, val := range variables {
		switch v := val.(type) {
		case string:
			if rule.modeType == singleModeType {
				fuzzedValue, interactURLs := rule.executeEvaluate(input, "", v, payload, input.InteractURLs)
				input.InteractURLs = interactURLs
				variables[k] = fuzzedValue
				graphQLData["variables"] = variables
				fuzzedGraphQLBodyBytes, _ := json.Marshal(graphQLData)
				strFuzzedGraphQLBody := string(fuzzedGraphQLBodyBytes)
				err = rule.buildBodyInput(input, strFuzzedGraphQLBody)
				// reset the original value
				variables[k] = v
				graphQLData["variables"] = variables
			} else {
				fuzzedValue, interactURLs := rule.executeEvaluate(input, "", v, payload, input.InteractURLs)
				input.InteractURLs = interactURLs
				variables[k] = fuzzedValue
			}
		default:
			continue
		}
	}
	if rule.modeType == multipleModeType {
		graphQLData["variables"] = variables
		fuzzedGraphQLBodyBytes, _ := json.Marshal(graphQLData)
		strFuzzedGraphQLBody := string(fuzzedGraphQLBodyBytes)
		err = rule.buildBodyInput(input, strFuzzedGraphQLBody)
	}

	return err
}

// returns a deep copy of the JSON data
func cloneJSON(data interface{}) interface{} {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var clonedData interface{}
	_ = json.Unmarshal(dataBytes, &clonedData)
	return clonedData
}

// returns a map of JSON paths to values of a JSON object
func flattenJSON(prefix string, value interface{}) map[string]interface{} {
	paths := make(map[string]interface{})
	recursivelyflattenJSON(prefix, value, paths)
	return paths
}

// recursively generate JSON path for all nested values
func recursivelyflattenJSON(prefix string, value interface{}, paths map[string]interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, val := range v {
			path := fmt.Sprintf("%s.%s", prefix, k)
			recursivelyflattenJSON(path, val, paths)
		}
	case []interface{}:
		for i, val := range v {
			path := fmt.Sprintf("%s.%d", prefix, i) // avoid [] notation for compatibility with sjson module
			recursivelyflattenJSON(path, val, paths)
		}
	default:
		paths[prefix] = v
	}
}
