package fuzz

import (
	"io"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// executePartRule executes part rules based on type
func (rule *Rule) executePartRule(input *ExecuteRuleInput, payload ValueOrKeyValue, component component.Component) error {
	return rule.executePartComponent(input, payload, component)
}

// checkRuleApplicableOnComponent checks if a rule is applicable on given component
func (rule *Rule) checkRuleApplicableOnComponent(component component.Component) bool {
	if rule.Part != component.Name() && !sliceutil.Contains(rule.Parts, component.Name()) && rule.partType != requestPartType {
		return false
	}
	foundAny := false
	_ = component.Iterate(func(key string, value interface{}) error {
		if rule.matchKeyOrValue(key, types.ToString(value)) {
			foundAny = true
			return io.EOF
		}
		return nil
	})
	return foundAny
}

// executePartComponent executes this rule on a given component and payload
func (rule *Rule) executePartComponent(input *ExecuteRuleInput, payload ValueOrKeyValue, ruleComponent component.Component) error {
	// Note: component needs to be cloned because they contain values copied by reference
	if payload.IsKV() {
		// for kv fuzzing
		return rule.executePartComponentOnKV(input, payload, ruleComponent.Clone())
	} else {
		// for value only fuzzing
		return rule.executePartComponentOnValues(input, payload.Value, payload.OriginalPayload, ruleComponent.Clone())
	}
}

// executePartComponentOnValues executes this rule on a given component and payload
// this supports both single and multiple [ruleType] modes
// i.e if component has multiple values, they can be replaced once or all depending on mode
func (rule *Rule) executePartComponentOnValues(input *ExecuteRuleInput, payloadStr, originalPayload string, ruleComponent component.Component) error {
	finalErr := ruleComponent.Iterate(func(key string, value interface{}) error {
		valueStr := types.ToString(value)
		if !rule.matchKeyOrValue(key, valueStr) {
			// ignore non-matching keys
			return nil
		}

		var evaluated, originalEvaluated string
		evaluated, input.InteractURLs = rule.executeEvaluate(input, key, valueStr, payloadStr, input.InteractURLs)
		if input.ApplyPayloadInitialTransformation != nil {
			evaluated = input.ApplyPayloadInitialTransformation(evaluated, input.AnalyzerParams)
			originalEvaluated, _ = rule.executeEvaluate(input, key, valueStr, originalPayload, input.InteractURLs)
		}

		if err := ruleComponent.SetValue(key, evaluated); err != nil {
			// gologger.Warning().Msgf("could not set value due to format restriction original(%s, %s[%T]) , new(%s,%s[%T])", key, valueStr, value, key, evaluated, evaluated)
			return nil
		}

		if rule.modeType == singleModeType {
			req, err := ruleComponent.Rebuild()
			if err != nil {
				return err
			}

			if qerr := rule.execWithInput(input, req, input.InteractURLs, ruleComponent, key, valueStr, originalEvaluated, valueStr, key, evaluated); qerr != nil {
				return qerr
			}
			// fmt.Printf("executed with value: %s\n", evaluated)
			err = ruleComponent.SetValue(key, valueStr) // change back to previous value for temp
			if err != nil {
				return err
			}
		}
		return nil
	})
	if finalErr != nil {
		return finalErr
	}

	// We do not support analyzers with
	// multiple payload mode.
	if rule.modeType == multipleModeType {
		req, err := ruleComponent.Rebuild()
		if err != nil {
			return err
		}
		if qerr := rule.execWithInput(input, req, input.InteractURLs, ruleComponent, "", "", "", "", "", ""); qerr != nil {
			err = qerr
			return err
		}
	}
	return nil
}

// executePartComponentOnKV executes this rule on a given component and payload
// currently only supports single mode
func (rule *Rule) executePartComponentOnKV(input *ExecuteRuleInput, payload ValueOrKeyValue, ruleComponent component.Component) error {
	var origKey string
	var origValue interface{}
	// when we have a key-value pair, iterate over only 1 value of the component
	// multiple values (aka multiple mode) not supported for this yet
	_ = ruleComponent.Iterate(func(key string, value interface{}) error {
		if key == payload.Key {
			origKey = key
			origValue = value
		}
		return nil
	})
	// iterate over given kv instead of component ones
	return func(key, value string) error {
		var evaluated string
		evaluated, input.InteractURLs = rule.executeEvaluate(input, key, "", value, input.InteractURLs)
		if err := ruleComponent.SetValue(key, evaluated); err != nil {
			return err
		}
		if rule.modeType == singleModeType {
			req, err := ruleComponent.Rebuild()
			if err != nil {
				return err
			}

			if qerr := rule.execWithInput(input, req, input.InteractURLs, ruleComponent, key, value, "", "", "", ""); qerr != nil {
				return qerr
			}

			// after building change back to original value to avoid repeating it in furthur requests
			if origKey != "" {
				err = ruleComponent.SetValue(origKey, types.ToString(origValue)) // change back to previous value for temp
				if err != nil {
					return err
				}
			} else {
				_ = ruleComponent.Delete(key) // change back to previous value for temp
			}
		}
		return nil
	}(payload.Key, payload.Value)
}

// execWithInput executes a rule with input via callback
func (rule *Rule) execWithInput(input *ExecuteRuleInput, httpReq *retryablehttp.Request, interactURLs []string, component component.Component, parameter, parameterValue, originalPayload, originalValue, key, value string) error {
	// If the parameter is a number, replace it with the parameter value
	// or if the parameter is empty and the parameter value is not empty
	// replace it with the parameter value
	actualParameter := parameter
	if _, err := strconv.Atoi(parameter); err == nil || (parameter == "" && parameterValue != "") {
		actualParameter = parameterValue
	}
	// If the parameter is frequent, skip it if the option is enabled
	if rule.options.FuzzParamsFrequency != nil {
		if rule.options.FuzzParamsFrequency.IsParameterFrequent(
			parameter,
			httpReq.URL.String(),
			rule.options.TemplateID,
		) {
			return nil
		}
	}
	request := GeneratedRequest{
		Request:         httpReq,
		InteractURLs:    interactURLs,
		DynamicValues:   input.Values,
		Component:       component,
		Parameter:       actualParameter,
		Key:             key,
		Value:           value,
		OriginalValue:   originalValue,
		OriginalPayload: originalPayload,
	}
	if !input.Callback(request) {
		return types.ErrNoMoreRequests
	}
	return nil
}

// executeEvaluate executes evaluation of payload on a key and value and
// returns completed values to be replaced and processed
// for fuzzing.
func (rule *Rule) executeEvaluate(input *ExecuteRuleInput, _, value, payload string, interactshURLs []string) (string, []string) {
	// TODO: Handle errors
	values := generators.MergeMaps(rule.options.Variables.GetAll(), map[string]interface{}{
		"value": value,
	}, rule.options.Options.Vars.AsMap(), input.Values)
	firstpass, _ := expressions.Evaluate(payload, values)
	interactData, interactshURLs := rule.options.Interactsh.Replace(firstpass, interactshURLs)
	evaluated, _ := expressions.Evaluate(interactData, values)
	replaced := rule.executeRuleTypes(input, value, evaluated)
	return replaced, interactshURLs
}

// executeRuleTypes executes replacement for a key and value
// ex: prefix, postfix, infix, replace , replace-regex
func (rule *Rule) executeRuleTypes(_ *ExecuteRuleInput, value, replacement string) string {
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
	case replaceRegexRuleType:
		returnValue = rule.replaceRegex.ReplaceAllString(value, replacement)
	}
	return returnValue
}
