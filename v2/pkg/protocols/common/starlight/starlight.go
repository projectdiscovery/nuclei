package starlight

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/starlight"
)

const resultPlaceholder = "script_result"

func Eval(expression string, parameters map[string]interface{}) (interface{}, error) {
	results, err := starlight.Eval(wrapResult(expression), parameters, nil)
	if err != nil {
		return nil, err
	}

	sr, ok := results[resultPlaceholder]
	if !ok {
		return nil, errors.New("result can't be retrieved")
	}
	return sr, nil
}

func EvalAsBool(expression string, parameters map[string]interface{}) (bool, error) {
	result, err := Eval(expression, parameters)
	if err != nil {
		return false, err
	}

	resultb, ok := result.(bool)
	if !ok {
		return false, errors.New("non boolean result")
	}
	return resultb, nil
}

func ExecScript(code string, parameters map[string]interface{}) (map[string]interface{}, error) {
	return starlight.Eval(code, parameters, nil)
}

func wrapResult(expr string) string {
	return fmt.Sprintf("%s=%s", resultPlaceholder, expr)
}
