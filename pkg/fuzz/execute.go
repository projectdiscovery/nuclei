package fuzz

import (
	"fmt"
	"io"
	"maps"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	ErrRuleNotApplicable = errkit.New("rule not applicable")
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
		return errkit.Newf("rule not applicable: invalid input url: %v", input.Input.MetaInput.Input)
	}
	if input.BaseRequest == nil && input.Input.MetaInput.ReqResp == nil {
		return errkit.Newf("rule not applicable: both base request and reqresp are nil for %v", input.Input.MetaInput.Input)
	}

	var finalComponentList []component.Component
	// match rule part with component name
	displayDebugFuzzPoints := make(map[string]map[string]string)
	for _, componentName := range component.Components {
		if rule.Part != componentName && !sliceutil.Contains(rule.Parts, componentName) && rule.partType != requestPartType {
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
		return errkit.Newf("rule not applicable: no component matched on this rule")
	}

	baseValues := input.Values
	baseInteractURLs := append([]string(nil), input.InteractURLs...)
	if rule.generator == nil {
		for _, component := range finalComponentList {
			var dataKeys map[string]struct{}

			optionVars := rule.options.Options.Vars.AsMap()
			constants := rule.options.Constants
			dataValues := rule.options.NewVariablesScope(baseValues, optionVars, constants)
			// get vars from variables while replacing interactsh urls
			evaluation := rule.options.Variables.EvaluateWithInteractshScope(dataValues, rule.options.Interactsh)
			evaluatedValues, interactURLs := evaluation.Values, evaluation.InteractURLs
			input.Values, dataKeys = mergeFuzzValueLayers(
				fuzzValueLayer{values: evaluatedValues, kind: fuzzValueTemplate},
				fuzzValueLayer{values: baseValues, kind: fuzzValueData},
				fuzzValueLayer{values: optionVars, kind: fuzzValueData},
				fuzzValueLayer{values: constants, kind: fuzzValueData},
			)
			// Replace template-text interactsh markers without evaluating runtime values.
			input.Values, interactURLs = rule.evaluateVarsWithInteractsh(input.Values, interactURLs, dataKeys)
			input.InteractURLs = mergeInteractURLs(baseInteractURLs, interactURLs)

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
			var interactURLs []string
			input.Values, interactURLs = rule.prepareGeneratorValues(values, baseValues)
			input.InteractURLs = mergeInteractURLs(baseInteractURLs, interactURLs)

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

func mergeInteractURLs(base, urls []string) []string {
	if len(base)+len(urls) == 0 {
		return nil
	}

	merged := make([]string, 0, len(base)+len(urls))
	seen := make(map[string]struct{}, len(base)+len(urls))

	for _, url := range base {
		if _, ok := seen[url]; ok {
			continue
		}

		seen[url] = struct{}{}
		merged = append(merged, url)
	}

	for _, url := range urls {
		if _, ok := seen[url]; ok {
			continue
		}

		seen[url] = struct{}{}
		merged = append(merged, url)
	}

	return merged
}

func (rule *Rule) prepareGeneratorValues(values, baseValues map[string]interface{}) (map[string]interface{}, []string) {
	optionVars := rule.options.Options.Vars.AsMap()
	constants := rule.options.Constants
	evaluationValues := rule.options.NewVariablesScope(values, baseValues, optionVars, constants)
	evaluation := rule.options.Variables.EvaluateWithInteractshScope(evaluationValues, rule.options.Interactsh)
	evaluatedValues, interactURLs := evaluation.Values, evaluation.InteractURLs
	inputValues, dataKeys := mergeFuzzValueLayers(
		fuzzValueLayer{values: values, kind: fuzzValueTemplate},
		fuzzValueLayer{values: evaluatedValues, kind: fuzzValueTemplate},
		fuzzValueLayer{values: baseValues, kind: fuzzValueData},
		fuzzValueLayer{values: optionVars, kind: fuzzValueData},
		fuzzValueLayer{values: constants, kind: fuzzValueData},
	)

	// Generator values are template-authored payload definitions until this
	// render. Runtime/base, CLI option, and constant values remain data.
	return rule.evaluateVarsWithInteractsh(inputValues, interactURLs, dataKeys)
}

type fuzzValueKind uint8

const (
	fuzzValueTemplate fuzzValueKind = iota
	fuzzValueData
)

type fuzzValueLayer struct {
	values map[string]interface{}
	kind   fuzzValueKind
}

func mergeFuzzValueLayers(layers ...fuzzValueLayer) (map[string]interface{}, map[string]struct{}) {
	size := 0
	for _, layer := range layers {
		size += len(layer.values)
	}

	values := make(map[string]interface{}, size)
	dataKeys := make(map[string]struct{})

	for _, layer := range layers {
		for key, value := range layer.values {
			values[key] = value
			if layer.kind == fuzzValueData {
				dataKeys[key] = struct{}{}
				continue
			}
			delete(dataKeys, key)
		}
	}

	if len(dataKeys) == 0 {
		return values, nil
	}

	return values, dataKeys
}

// evaluateVars evaluates variables in a string using available executor options
func (rule *Rule) evaluateVars(input string) (string, error) {
	if rule.options == nil {
		return input, nil
	}

	data := generators.MergeMaps(
		rule.options.Variables.GetAll(),
		rule.options.Constants,
		rule.options.Options.Vars.AsMap(),
	)

	exprs := expressions.FindExpressions(input, marker.ParenthesisOpen, marker.ParenthesisClose, data)

	err := expressions.ContainsUnresolvedVariables(exprs...)
	if err != nil {
		return input, err
	}

	result, err := render.Render(render.Input{
		Text:   input,
		Values: data,
	})
	if err != nil {
		return input, err
	}

	return result.Text, nil
}

// evaluateVarsWithInteractsh renders template-text values and leaves runtime data untouched.
func (rule *Rule) evaluateVarsWithInteractsh(data map[string]interface{}, interactshUrls []string, dataKeys map[string]struct{}) (map[string]interface{}, []string) {
	// Check if Interactsh options are configured
	if rule.options.Interactsh != nil {
		data = maps.Clone(data)

		interactshUrlsMap := make(map[string]struct{})
		for _, url := range interactshUrls {
			interactshUrlsMap[url] = struct{}{}
		}

		interactshUrls = mapsutil.GetKeys(interactshUrlsMap)

		// Iterate through template-text data to replace Interactsh URL markers.
		for k, v := range data {
			if _, ok := dataKeys[k]; ok {
				continue
			}

			got, err := render.Render(render.Input{
				Text:         fmt.Sprint(v),
				Values:       data,
				Interactsh:   rule.options.Interactsh,
				InteractURLs: interactshUrls,
			})
			if err == nil {
				data[k] = got.Text
				for _, url := range got.InteractURLs {
					if _, ok := interactshUrlsMap[url]; ok {
						continue
					}

					interactshUrlsMap[url] = struct{}{}
					interactshUrls = append(interactshUrls, url)
				}
			}
		}
	}

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
				var err error

				evaluated, input.InteractURLs, err = rule.executeEvaluate(input, key, "", value, input.InteractURLs)
				if err != nil {
					gotErr = err

					return false
				}

				if err := ruleComponent.SetValue(key, evaluated); err != nil {
					return true
				}

				return true
			})

			if gotErr != nil {
				return gotErr
			}

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

	// eval vars in "keys"
	for _, key := range rule.Keys {
		evaluatedKey, err := rule.evaluateVars(key)
		if err != nil {
			return errors.Wrap(err, "could not evaluate key")
		}

		rule.keysMap[strings.ToLower(evaluatedKey)] = struct{}{}
	}

	// eval vars in "values"
	for _, value := range rule.ValuesRegex {
		evaluatedValue, err := rule.evaluateVars(value)
		if err != nil {
			return errors.Wrap(err, "could not evaluate value regex")
		}

		compiled, err := regexp.Compile(evaluatedValue)
		if err != nil {
			return errors.Wrap(err, "could not compile value regex")
		}

		rule.valuesRegex = append(rule.valuesRegex, compiled)
	}

	// eval vars in "keys-regex"
	for _, value := range rule.KeysRegex {
		evaluatedValue, err := rule.evaluateVars(value)
		if err != nil {
			return errors.Wrap(err, "could not evaluate key regex")
		}

		compiled, err := regexp.Compile(evaluatedValue)
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

		evalReplaceRegex, err := rule.evaluateVars(rule.ReplaceRegex)
		if err != nil {
			return errors.Wrap(err, "could not evaluate replace regex")
		}

		compiled, err := regexp.Compile(evalReplaceRegex)
		if err != nil {
			return errors.Wrap(err, "could not compile replace regex")
		}

		rule.replaceRegex = compiled
	}

	return nil
}
