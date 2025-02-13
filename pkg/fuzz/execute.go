package fuzz

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	fuzzStats "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
	// DisplayFuzzPoints is a flag to display fuzz points
	DisplayFuzzPoints bool

	// ApplyPayloadInitialTransformation is an optional function
	// to transform the payload initially based on analyzer rules
	ApplyPayloadInitialTransformation func(string, map[string]interface{}) string
	AnalyzerParams                    map[string]interface{}
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
	// Parameter being fuzzed
	Parameter string

	// Key is the key for the request
	Key string
	// Value is the value for the request
	Value string
	// OriginalValue is the original value for the request
	OriginalValue string
	// OriginalPayload is the original payload for the request
	OriginalPayload string
}

// Execute executes a fuzzing rule accepting a callback on which
// generated requests are returned.
//
// Input is not thread safe and should not be shared between concurrent
// goroutines.
func (rule *Rule) Execute(input *ExecuteRuleInput) (err error) {
	if !rule.isInputURLValid(input.Input) {
		return ErrRuleNotApplicable.Msgf("invalid input url: %v", input.Input.MetaInput.Input)
	}
	if input.BaseRequest == nil && input.Input.MetaInput.ReqResp == nil {
		return ErrRuleNotApplicable.Msgf("both base request and reqresp are nil for %v", input.Input.MetaInput.Input)
	}

	var finalComponentList []component.Component
	// match rule part with component name
	displayDebugFuzzPoints := make(map[string]map[string]string)
	for _, componentName := range component.Components {
		if !(rule.Part == componentName || sliceutil.Contains(rule.Parts, componentName) || rule.partType == requestPartType) {
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
		// Debugging display for fuzz points
		if input.DisplayFuzzPoints {
			displayDebugFuzzPoints[componentName] = make(map[string]string)
			_ = component.Iterate(func(key string, value interface{}) error {
				displayDebugFuzzPoints[componentName][key] = fmt.Sprintf("%v", value)
				return nil
			})
		}

		if rule.options.FuzzStatsDB != nil {
			_ = component.Iterate(func(key string, value interface{}) error {
				rule.options.FuzzStatsDB.RecordComponentEvent(fuzzStats.ComponentEvent{
					URL:           input.Input.MetaInput.Target(),
					ComponentType: componentName,
					ComponentName: fmt.Sprintf("%v", value),
				})
				return nil
			})
		}

		finalComponentList = append(finalComponentList, component)
	}
	if len(displayDebugFuzzPoints) > 0 {
		marshalled, _ := json.MarshalIndent(displayDebugFuzzPoints, "", "  ")
		gologger.Info().Msgf("[%s] Fuzz points for %s [%s]\n%s\n", rule.options.TemplateID, input.Input.MetaInput.Input, input.BaseRequest.Method, string(marshalled))
	}

	if len(finalComponentList) == 0 {
		return ErrRuleNotApplicable.Msgf("no component matched on this rule")
	}

	baseValues := input.Values
	if rule.generator == nil {
		for _, component := range finalComponentList {
			// get vars from variables while replacing interactsh urls
			evaluatedValues, interactURLs := rule.options.Variables.EvaluateWithInteractsh(baseValues, rule.options.Interactsh)
			input.Values = generators.MergeMaps(evaluatedValues, baseValues, rule.options.Options.Vars.AsMap(), rule.options.Constants)
			// evaluate all vars with interactsh
			input.Values, interactURLs = rule.evaluateVarsWithInteractsh(input.Values, interactURLs)
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
			// get vars from variables while replacing interactsh urls
			evaluatedValues, interactURLs := rule.options.Variables.EvaluateWithInteractsh(generators.MergeMaps(values, baseValues), rule.options.Interactsh)
			input.Values = generators.MergeMaps(values, evaluatedValues, baseValues, rule.options.Options.Vars.AsMap(), rule.options.Constants)
			// evaluate all vars with interactsh
			input.Values, interactURLs = rule.evaluateVarsWithInteractsh(input.Values, interactURLs)
			input.InteractURLs = interactURLs

			if err := rule.executeRuleValues(input, component); err != nil {
				if err == io.EOF {
					return nil
				}
				gologger.Warning().Msgf("[%s] Could not execute rule: %s\n", rule.options.TemplateID, err)
				return err
			}
		}
	}
	return nil
}

// evaluateVarsWithInteractsh evaluates the variables with Interactsh URLs and updates them accordingly.
func (rule *Rule) evaluateVarsWithInteractsh(data map[string]interface{}, interactshUrls []string) (map[string]interface{}, []string) {
	// Check if Interactsh options are configured
	if rule.options.Interactsh != nil {
		interactshUrlsMap := make(map[string]struct{})
		for _, url := range interactshUrls {
			interactshUrlsMap[url] = struct{}{}
		}
		interactshUrls = mapsutil.GetKeys(interactshUrlsMap)
		// Iterate through the data to replace and evaluate variables with Interactsh URLs
		for k, v := range data {
			value := fmt.Sprint(v)
			// Replace variables with Interactsh URLs and collect new URLs
			got, oastUrls := rule.options.Interactsh.Replace(value, interactshUrls)
			if got != value {
				data[k] = got
			}
			// Append new OAST URLs if any
			if len(oastUrls) > 0 {
				for _, url := range oastUrls {
					if _, ok := interactshUrlsMap[url]; !ok {
						interactshUrlsMap[url] = struct{}{}
						interactshUrls = append(interactshUrls, url)
					}
				}
			}
			// Evaluate the replaced data
			evaluatedData, err := expressions.Evaluate(got, data)
			if err == nil {
				// Update the data if there is a change after evaluation
				if evaluatedData != got {
					data[k] = evaluatedData
				}
			}
		}
	}
	// Return the updated data and Interactsh URLs without any error
	return data, interactshUrls
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
func (rule *Rule) executeRuleValues(input *ExecuteRuleInput, ruleComponent component.Component) error {
	// if we are only fuzzing values
	if len(rule.Fuzz.Value) > 0 {
		for _, value := range rule.Fuzz.Value {
			originalPayload := value

			if err := rule.executePartRule(input, ValueOrKeyValue{Value: value, OriginalPayload: originalPayload}, ruleComponent); err != nil {
				if component.IsErrSetValue(err) {
					// this are errors due to format restrictions
					// ex: fuzzing string value in a json int field
					continue
				}
				return err
			}
		}
		return nil
	}

	// if we are fuzzing both keys and values
	if rule.Fuzz.KV != nil {
		var gotErr error
		rule.Fuzz.KV.Iterate(func(key, value string) bool {
			if err := rule.executePartRule(input, ValueOrKeyValue{Key: key, Value: value}, ruleComponent); err != nil {
				if component.IsErrSetValue(err) {
					// this are errors due to format restrictions
					// ex: fuzzing string value in a json int field
					return true
				}
				gotErr = err
				return false
			}
			return true
		})
		// if mode is multiple now build and execute it
		if rule.modeType == multipleModeType {
			rule.Fuzz.KV.Iterate(func(key, value string) bool {
				var evaluated string
				evaluated, input.InteractURLs = rule.executeEvaluate(input, key, "", value, input.InteractURLs)
				if err := ruleComponent.SetValue(key, evaluated); err != nil {
					return true
				}
				return true
			})
			req, err := ruleComponent.Rebuild()
			if err != nil {
				return err
			}
			if gotErr := rule.execWithInput(input, req, input.InteractURLs, ruleComponent, "", "", "", "", "", ""); gotErr != nil {
				return gotErr
			}
		}
		return gotErr
	}

	// something else is wrong
	return fmt.Errorf("no fuzz values specified")
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
	}
	if rule.Part == "" && len(rule.Parts) == 0 {
		return errors.Errorf("no part specified for rule")
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
