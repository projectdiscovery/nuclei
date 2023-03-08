package variables

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Todo: global flags should be replaced with per-structure one
var LazyEval bool

// Variables is a key-value pair of strings that can be used
// throughout template.
type Variables struct {
	utils.InsertionOrderedStringMap `yaml:"-" json:"-"`
}

func (variables *Variables) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "map[string]string",
		Title:       "variables for the request",
		Description: "Additional variables for the request",
	}
	return gotType
}

func (variables *Variables) UnmarshalYAML(unmarshal func(interface{}) error) error {
	variables.InsertionOrderedStringMap = utils.InsertionOrderedStringMap{}
	if err := unmarshal(&variables.InsertionOrderedStringMap); err != nil {
		return err
	}

	if LazyEval {
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
func (variables *Variables) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, variables.Len())
	variables.ForEach(func(key string, value interface{}) {
		result[key] = evaluateVariableValue(types.ToString(value), values, result)
	})
	return result
}

// EvaluateWithInteractsh returns evaluation results of variables with interactsh
func (variables *Variables) EvaluateWithInteractsh(values map[string]interface{}, interact *interactsh.Client) (map[string]interface{}, []string) {
	result := make(map[string]interface{}, variables.Len())

	var interactURLs []string
	variables.ForEach(func(key string, value interface{}) {
		valueString := types.ToString(value)
		if strings.Contains(valueString, expressions.ExpMarkerParenthesis.String("interactsh-url")) {
			valueString, interactURLs = interact.ReplaceMarkers(valueString, interactURLs)
		}
		result[key] = evaluateVariableValue(valueString, values, result)
	})
	return result, interactURLs
}

// evaluateVariableValue expression and returns final value
func evaluateVariableValue(expression string, valuesMaps ...map[string]interface{}) string {
	finalMap := generators.MergeMaps(valuesMaps...)
	result, err := expressions.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}

	return result
}
