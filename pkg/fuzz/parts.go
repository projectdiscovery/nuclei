package fuzz

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// executePartRule executes part rules based on type
func (rule *Rule) executePartRule(input *ExecuteRuleInput, payload string, component component.Component) error {
	return rule.executePartComponent(input, payload, component)
}

// executePartComponent executes component part rules
func (rule *Rule) executePartComponent(input *ExecuteRuleInput, payload string, component component.Component) error {
	var finalErr error
	component.Iterate(func(key string, value interface{}) {
		valueStr := types.ToString(value)
		if !rule.matchKeyOrValue(key, valueStr) {
			return
		}

		var evaluated string
		evaluated, input.InteractURLs = rule.executeEvaluate(input, key, valueStr, payload, input.InteractURLs)
		if err := component.SetValue(key, evaluated); err != nil {
			return
		}

		if rule.modeType == singleModeType {
			req, err := component.Rebuild()
			if err != nil {
				return
			}

			if qerr := rule.buildInput(input, req, input.InteractURLs, component, key, evaluated, valueStr); qerr != nil {
				finalErr = qerr
				return
			}
			err = component.SetValue(key, valueStr) // change back to previous value for temp
			if err != nil {
				finalErr = err
				return
			}
		}
	})
	if finalErr != nil {
		return finalErr
	}

	// We do not support analyzers with
	// multiple payload mode.
	if rule.modeType == multipleModeType {
		req, err := component.Rebuild()
		if err != nil {
			return err
		}

		if qerr := rule.buildInput(input, req, input.InteractURLs, component, "", "", ""); qerr != nil {
			err = qerr
			return err
		}
	}
	return nil
}

// buildInput returns created request for a Query Input
func (rule *Rule) buildInput(input *ExecuteRuleInput, httpReq *retryablehttp.Request, interactURLs []string, component component.Component, key, value, originalValue string) error {
	request := GeneratedRequest{
		Request:       httpReq,
		InteractURLs:  interactURLs,
		DynamicValues: input.Values,
		Component:     component,
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
	}, rule.options.Options.Vars.AsMap(), rule.options.Variables.GetAll())
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
