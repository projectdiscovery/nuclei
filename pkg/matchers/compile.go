package matchers

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
)

// CompileMatchers performs the initial setup operation on a matcher
func (m *Matcher) CompileMatchers() error {
	var ok bool

	// Setup the matcher type
	m.matcherType, ok = MatcherTypes[m.Type]
	if !ok {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	}

	// Compile the regexes
	for _, regex := range m.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}

		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile the dsl expressions
	for _, dsl := range m.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dsl, helperFunctions())
		if err != nil {
			return fmt.Errorf("could not compile dsl: %s", dsl)
		}

		m.dslCompiled = append(m.dslCompiled, compiled)
	}

	// Setup the condition type, if any.
	if m.Condition != "" {
		m.condition, ok = ConditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	} else {
		m.condition = ORCondition
	}

	// Setup the part of the request to match, if any.
	if m.Part != "" {
		m.part, ok = PartTypes[m.Part]
		if !ok {
			return fmt.Errorf("unknown matcher part specified: %s", m.Part)
		}
	} else {
		m.part = BodyPart
	}
	return nil
}

func helperFunctions() (functions map[string]govaluate.ExpressionFunction) {
	functions = make(map[string]govaluate.ExpressionFunction)
	functions["len"] = func(args ...interface{}) (interface{}, error) {
		length := len(args[0].(string))
		return (float64)(length), nil
	}
	functions["base64"] = func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(args[0].(string)))
		return sEnc, nil
	}
	functions["md5"] = func(args ...interface{}) (interface{}, error) {
		hash := md5.Sum([]byte(args[0].(string)))
		return hex.EncodeToString(hash[:]), nil
	}
	functions["sha256"] = func(args ...interface{}) (interface{}, error) {
		return sha256.Sum256([]byte(args[0].(string))), nil
	}
	functions["contains"] = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(args[0].(string), args[1].(string)), nil
	}
	functions["regex"] = func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(args[0].(string))
		if err != nil {
			return nil, err
		}
		return compiled.MatchString(args[1].(string)), nil
	}

	return
}
