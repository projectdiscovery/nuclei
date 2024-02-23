package fuzz

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	ErrRuleNotApplicable = errorutil.NewWithFmt("rule not applicable : %v")
)

// IsErrRuleNotApplicable checks if an error is due to rule not applicable
func IsErrRuleNotApplicable(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "rule not applicable") {
		return true
	}
	return false
}

// ExecuteRuleInput is the input for rule Execute function
type ExecuteRuleInput struct {
	// Input is the context args input
	Input *contextargs.Context
	// Callback is the callback for generated rule requests
	Callback func(GeneratedRequest) bool
	// InteractURLs contains interact urls for execute call
	InteractURLs []string
	// Values contains dynamic values for the rule
	Values map[string]interface{}
	// BaseRequest is the base http request for fuzzing rule
	BaseRequest *retryablehttp.Request
}

// GeneratedRequest is a single generated request for rule
type GeneratedRequest struct {
	// Request is the http request for rule
	Request *retryablehttp.Request
	// InteractURLs is the list of interactsh urls
	InteractURLs []string
	// DynamicValues contains dynamic values map
	DynamicValues map[string]interface{}
	// Component is the component for the request
	Component component.Component
}

// Execute executes a fuzzing rule accepting a callback on which
// generated requests are returned.
//
// Input is not thread safe and should not be shared between concurrent
// goroutines.
func (rule *Rule) Execute(input *ExecuteRuleInput) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("got panic while executing rule: %v", r)
		}
	}()
	if !rule.isInputURLValid(input.Input) {
		return ErrRuleNotApplicable.Msgf("invalid input url: %v", input.Input.MetaInput.Input)
	}
	if input.BaseRequest == nil && input.Input.MetaInput.ReqResp == nil {
		return ErrRuleNotApplicable.Msgf("both base request and reqresp are nil for %v", input.Input.MetaInput.Input)
	}

	var finalComponentList []component.Component
	// match rule part with component name
	for _, componentName := range component.Components {
		if rule.partType != requestPartType && rule.Part != componentName {
			continue
		}
		component := component.New(componentName)
		discovered, err := component.Parse(input.BaseRequest)
		if err != nil {
			gologger.Verbose().Msgf("Could not parse component %s: %s\n", componentName, err)
			continue
		}
		if !discovered {
			continue
		}
		// check rule applicable on this component
		if !rule.checkRuleApplicableOnComponent(component) {
			continue
		}
		finalComponentList = append(finalComponentList, component)
	}

	if len(finalComponentList) == 0 {
		return ErrRuleNotApplicable.Msgf("no component matched on this rule")
	}

	baseValues := input.Values
	if rule.generator == nil {
		for _, component := range finalComponentList {
			evaluatedValues, interactURLs := rule.options.Variables.EvaluateWithInteractsh(baseValues, rule.options.Interactsh)
			input.Values = generators.MergeMaps(evaluatedValues, baseValues, rule.options.Constants)
			input.InteractURLs = interactURLs
			err := rule.executeRuleValues(input, component)
			if err != nil {
				return err
			}
		}
		return nil
	}
mainLoop:
	for _, component := range finalComponentList {
		iterator := rule.generator.NewIterator()
		for {
			values, next := iterator.Value()
			if !next {
				continue mainLoop
			}
			evaluatedValues, interactURLs := rule.options.Variables.EvaluateWithInteractsh(generators.MergeMaps(values, baseValues), rule.options.Interactsh)
			input.InteractURLs = interactURLs
			input.Values = generators.MergeMaps(values, evaluatedValues, baseValues, rule.options.Constants)

			if err := rule.executeRuleValues(input, component); err != nil {
				if err == io.EOF {
					return nil
				}
				gologger.Warning().Msgf("Could not execute rule: %s\n", err)
				return err
			}
		}
	}
	return nil
}

// isInputURLValid returns true if url is valid after parsing it
func (rule *Rule) isInputURLValid(input *contextargs.Context) bool {
	if input == nil || input.MetaInput == nil || input.MetaInput.Input == "" {
		return false
	}
	_, err := urlutil.Parse(input.MetaInput.Input)
	return err == nil
}

// executeRuleValues executes a rule with a set of values
func (rule *Rule) executeRuleValues(input *ExecuteRuleInput, component component.Component) error {
	if len(rule.Fuzz.Value) > 0 {
		for _, value := range rule.Fuzz.Value {
			if err := rule.executePartRule(input, ValueOrKeyValue{Value: value}, component); err != nil {
				return err
			}
		}
		return nil
	} else if rule.Fuzz.KV != nil {
		var gotErr error
		rule.Fuzz.KV.Iterate(func(key, value string) bool {
			if err := rule.executePartRule(input, ValueOrKeyValue{Key: key, Value: value}, component); err != nil {
				gotErr = err
				return false
			}
			return true
		})
		return gotErr
	} else {
		return fmt.Errorf("no fuzz values specified")
	}
}

// Compile compiles a fuzzing rule and initializes it for operation
func (rule *Rule) Compile(generator *generators.PayloadGenerator, options *protocols.ExecutorOptions) error {
	// If a payload generator is specified from base request, use it
	// for payload values.
	if generator != nil {
		rule.generator = generator
	}
	rule.options = options

	// Resolve the default enums
	if rule.Mode != "" {
		if valueType, ok := stringToModeType[rule.Mode]; !ok {
			return errors.Errorf("invalid mode value specified: %s", rule.Mode)
		} else {
			rule.modeType = valueType
		}
	} else {
		rule.modeType = multipleModeType
	}
	if rule.Part != "" {
		if valueType, ok := stringToPartType[rule.Part]; !ok {
			return errors.Errorf("invalid part value specified: %s", rule.Part)
		} else {
			rule.partType = valueType
		}
	} else {
		rule.partType = queryPartType
	}

	if rule.Type != "" {
		if valueType, ok := stringToRuleType[rule.Type]; !ok {
			return errors.Errorf("invalid type value specified: %s", rule.Type)
		} else {
			rule.ruleType = valueType
		}
	} else {
		rule.ruleType = replaceRuleType
	}

	// Initialize other required regexes and maps
	if len(rule.Keys) > 0 {
		rule.keysMap = make(map[string]struct{})
	}
	for _, key := range rule.Keys {
		rule.keysMap[strings.ToLower(key)] = struct{}{}
	}
	for _, value := range rule.ValuesRegex {
		compiled, err := regexp.Compile(value)
		if err != nil {
			return errors.Wrap(err, "could not compile value regex")
		}
		rule.valuesRegex = append(rule.valuesRegex, compiled)
	}
	for _, value := range rule.KeysRegex {
		compiled, err := regexp.Compile(value)
		if err != nil {
			return errors.Wrap(err, "could not compile key regex")
		}
		rule.keysRegex = append(rule.keysRegex, compiled)
	}
	if rule.ruleType != replaceRegexRuleType {
		if rule.ReplaceRegex != "" {
			return errors.Errorf("replace-regex is only applicable for replace and replace-regex rule types")
		}
	} else {
		if rule.ReplaceRegex == "" {
			return errors.Errorf("replace-regex is required for replace-regex rule type")
		}
		compiled, err := regexp.Compile(rule.ReplaceRegex)
		if err != nil {
			return errors.Wrap(err, "could not compile replace regex")
		}
		rule.replaceRegex = compiled
	}
	return nil
}
