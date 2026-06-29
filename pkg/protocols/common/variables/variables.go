package variables

import (
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Variable is a key-value pair of strings that can be used
// throughout template.
type Variable struct {
	// LazyEval is used to evaluate variables lazily if it using any expression
	// or global variables.
	LazyEval                        bool `yaml:"-" json:"-"`
	utils.InsertionOrderedStringMap `yaml:"-" json:"-"`
}

// Evaluation contains variable values and the subset produced from template
// variable text.
type Evaluation struct {
	Values         map[string]interface{}
	TemplateValues map[string]interface{}
	InteractURLs   []string
}

func (variables Variable) JSONSchema() *jsonschema.Schema {
	gotType := &jsonschema.Schema{
		Type:                 "object",
		Title:                "variables for the request",
		Description:          "Additional variables for the request",
		AdditionalProperties: &jsonschema.Schema{},
	}
	return gotType
}

func (variables *Variable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	variables.InsertionOrderedStringMap = utils.InsertionOrderedStringMap{}
	if err := unmarshal(&variables.InsertionOrderedStringMap); err != nil {
		return err
	}

	if variables.LazyEval || variables.checkForLazyEval() {
		return nil
	}

	evaluated := variables.Evaluate(map[string]interface{}{})

	for k, v := range evaluated {
		variables.Set(k, v)
	}
	return nil
}

func (variables *Variable) UnmarshalJSON(data []byte) error {
	variables.InsertionOrderedStringMap = utils.InsertionOrderedStringMap{}
	if err := json.Unmarshal(data, &variables.InsertionOrderedStringMap); err != nil {
		return err
	}
	evaluated := variables.Evaluate(map[string]interface{}{})

	for k, v := range evaluated {
		variables.Set(k, v)
	}
	return nil
}

// Evaluate returns a finished map of variables based on set values
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	return variables.EvaluateScope(NewScope().AddData(values)).Values
}

// EvaluateScope returns evaluated variables and records which returned values
// were produced from template variable text.
func (variables *Variable) EvaluateScope(scope *Scope) Evaluation {
	result := make(map[string]interface{}, variables.Len())
	templateValues := make(map[string]interface{}, variables.Len())
	combined := scope.clone()

	variables.ForEach(func(key string, value interface{}) {
		if existingValue, ok := combined.get(key); ok && existingValue.kind == scopeValueData {
			result[key] = existingValue.value
			combined.AddDataValue(key, existingValue.value)

			return
		}

		if sliceValue, ok := value.([]interface{}); ok {
			// slices cannot be evaluated
			result[key] = sliceValue
			templateValues[key] = sliceValue
			combined.AddTemplateValue(key, sliceValue)

			return
		}

		valueString := types.ToString(value)
		evaluated := evaluateVariableValueWithMap(valueString, combined.Values())
		result[key] = evaluated
		templateValues[key] = evaluated
		combined.AddTemplateValue(key, evaluated)
	})

	return Evaluation{Values: result, TemplateValues: templateValues}
}

// GetAll returns all variables as a map
func (variables *Variable) GetAll() map[string]interface{} {
	result := make(map[string]interface{}, variables.Len())
	variables.ForEach(func(key string, value interface{}) {
		result[key] = value
	})

	return result
}

// EvaluateWithInteractsh returns evaluation results of variables with interactsh
func (variables *Variable) EvaluateWithInteractsh(values map[string]interface{}, interact *interactsh.Client) (map[string]interface{}, []string) {
	evaluation := variables.EvaluateWithInteractshScope(NewScope().AddData(values), interact)
	return evaluation.Values, evaluation.InteractURLs
}

// EvaluateWithInteractshScope returns evaluated variables, source-level
// Interactsh URLs, and the subset of values produced from template variable
// text.
func (variables *Variable) EvaluateWithInteractshScope(scope *Scope, interact render.URLSource) Evaluation {
	result := make(map[string]interface{}, variables.Len())
	templateValues := make(map[string]interface{}, variables.Len())
	combined := scope.clone()

	var interactURLs []string

	variables.ForEach(func(key string, value interface{}) {
		if existingValue, ok := combined.get(key); ok && existingValue.kind == scopeValueData {
			result[key] = existingValue.value
			combined.AddDataValue(key, existingValue.value)

			return
		}

		if sliceValue, ok := value.([]interface{}); ok {
			// slices cannot be evaluated
			result[key] = sliceValue
			templateValues[key] = sliceValue
			combined.AddTemplateValue(key, sliceValue)

			return
		}

		valueString := types.ToString(value)
		evaluated, gotURLs := renderVariableValueWithInteractsh(valueString, combined.Values(), interact, interactURLs)
		result[key] = evaluated
		templateValues[key] = evaluated
		combined.AddTemplateValue(key, evaluated)
		interactURLs = gotURLs
	})

	return Evaluation{Values: result, TemplateValues: templateValues, InteractURLs: interactURLs}
}

// evaluateVariableValue expression and returns final value.
//
// Deprecated: use evaluateVariableValueWithMap instead to avoid repeated map
// merging overhead.
func evaluateVariableValue(expression string, values, processing map[string]interface{}) string { // nolint
	finalMap := generators.MergeMaps(values, processing)
	result, err := render.Render(render.Input{
		Text:   expression,
		Values: finalMap,
	})
	if err != nil {
		return expression
	}

	return result.Text
}

// evaluateVariableValueWithMap evaluates an expression with a pre-merged map.
func evaluateVariableValueWithMap(expression string, combinedMap map[string]interface{}) string {
	result, err := render.Render(render.Input{
		Text:   expression,
		Values: combinedMap,
	})
	if err != nil {
		return expression
	}

	return result.Text
}

func renderVariableValueWithInteractsh(expression string, combinedMap map[string]interface{}, interact render.URLSource, interactURLs []string) (string, []string) {
	result, err := render.Render(render.Input{
		Text:         expression,
		Values:       combinedMap,
		Interactsh:   interact,
		InteractURLs: interactURLs,
	})
	if err != nil {
		return result.Text, result.InteractURLs
	}

	return result.Text, result.InteractURLs
}

// checkForLazyEval checks if the variables have any lazy evaluation i.e any dsl function
// and sets the flag accordingly.
func (variables *Variable) checkForLazyEval() bool {
	var needsLazy bool

	variables.ForEach(func(key string, value interface{}) {
		if needsLazy {
			return
		}

		for _, v := range protocolutils.KnownVariables {
			if stringsutil.ContainsAny(types.ToString(value), v) {
				needsLazy = true
				return
			}
		}

		// this is a hotfix and not the best way to do it
		// will be refactored once we move scan state to scanContext (see: https://github.com/projectdiscovery/nuclei/issues/4631)
		if strings.Contains(types.ToString(value), "interactsh-url") {
			needsLazy = true
			return
		}

		if hasUndefinedParams(types.ToString(value), variables) {
			needsLazy = true
			return
		}
	})

	variables.LazyEval = needsLazy

	return variables.LazyEval
}

// hasUndefinedParams checks if a variable value contains expressions that ref
// parameters not defined in the current variable scope, indicating it needs
// runtime context.
func hasUndefinedParams(value string, variables *Variable) bool {
	exprs := expressions.FindExpressions(value, marker.ParenthesisOpen, marker.ParenthesisClose, map[string]interface{}{})
	if len(exprs) == 0 {
		return false
	}

	definedVars := make(map[string]struct{})
	variables.ForEach(func(key string, _ interface{}) {
		definedVars[key] = struct{}{}
	})

	for _, expr := range exprs {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, dsl.HelperFunctions)
		if err != nil {
			// NOTE(dwisiswant0): here, it might need runtime context.
			return true
		}

		vars := compiled.Vars()
		for _, paramName := range vars {
			// NOTE(dwisiswant0): also here, if it's not in our defined vars.
			if _, exists := definedVars[paramName]; !exists {
				return true
			}
		}
	}

	return false
}
