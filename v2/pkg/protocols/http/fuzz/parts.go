package fuzz

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/retryablehttp-go"
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
	requestURL := *input.URL
	temp := url.Values{}
	for k, v := range input.URL.Query() {
		temp[k] = v
	}

	var interactURLs []string
	for key, values := range input.URL.Query() {
		var value string
		if len(values) > 0 {
			value = values[0]
		}
		if !rule.matchKeyOrValue(key, value) {
			continue
		}
		var evaluated string
		evaluated, interactURLs = rule.executeEvaluate(input, key, value, payload, interactURLs)
		temp.Set(key, evaluated)

		if rule.modeType == singleModeType {
			requestURL.RawQuery = temp.Encode()
			if err := rule.buildQueryInput(input, requestURL, interactURLs); err != nil {
				return err
			}
			temp.Set(key, value) // change back to previous value for temp
		}
	}

	if rule.modeType == multipleModeType {
		requestURL.RawQuery = temp.Encode()
		if err := rule.buildQueryInput(input, requestURL, interactURLs); err != nil {
			return err
		}
	}
	return nil
}

// buildQueryInput returns created request for a Query Input
func (rule *Rule) buildQueryInput(input *ExecuteRuleInput, parsed url.URL, interactURLs []string) error {
	req, err := retryablehttp.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

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

// executeEvaluate executes evaluation of payload on a key and value and
// returns completed values to be replaced and processed
// for fuzzing.
func (rule *Rule) executeEvaluate(input *ExecuteRuleInput, key, value, payload string, interactshURLs []string) (string, []string) {
	firstpass := replacer.Replace(payload, input.Values)
	interactData, interactshURLs := rule.options.Interactsh.ReplaceMarkers(firstpass, interactshURLs)
	evaluated := replacer.Replace(interactData, input.Values)
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
