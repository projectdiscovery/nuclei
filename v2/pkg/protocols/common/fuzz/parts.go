package fuzz

import (
	"context"
	"net/http"
	"strings"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	urlutil "github.com/projectdiscovery/utils/url"
)

// executePartRule executes part rules based on type
func (rule *Rule) executePartRule(input *ExecuteRuleInput, payload string) error {
	switch rule.partType {
	case queryPartType:
		return rule.executeQueryPartRule(input, payload)
	}
	return nil
}

// executeQueryPartRule executes query part rules
func (rule *Rule) executeQueryPartRule(input *ExecuteRuleInput, payload string) error {
	requestURL, err := urlutil.Parse(input.Input.MetaInput.Input)
	if err != nil {
		return err
	}
	origRequestURL := requestURL.Clone()
	// clone the params to avoid modifying the original
	temp := origRequestURL.Params.Clone()

	origRequestURL.Query().Iterate(func(key string, values []string) bool {
		cloned := sliceutil.Clone(values)
		for i, value := range values {
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
