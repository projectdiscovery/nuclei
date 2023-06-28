package fuzz

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
)

// Rule is a single rule which describes how to fuzz the request
type Rule struct {
	// description: |
	//   Type is the type of fuzzing rule to perform.
	//
	//   replace replaces the values entirely. prefix prefixes the value. postfix postfixes the value
	//   and infix places between the values.
	// values:
	//   - "replace"
	//   - "prefix"
	//   - "postfix"
	//   - "infix"
	Type     string `yaml:"type,omitempty" json:"type,omitempty" jsonschema:"title=type of rule,description=Type of fuzzing rule to perform,enum=replace,enum=prefix,enum=postfix,enum=infix"`
	ruleType ruleType
	// description: |
	//   Part is the part of request to fuzz.
	//
	//   query fuzzes the query part of url. More parts will be added later.
	// values:
	//   - "query"
	Part     string `yaml:"part,omitempty" json:"part,omitempty" jsonschema:"title=part of rule,description=Part of request rule to fuzz,enum=query"`
	partType partType
	// description: |
	//   Mode is the mode of fuzzing to perform.
	//
	//   single fuzzes one value at a time. multiple fuzzes all values at same time.
	// values:
	//   - "single"
	//   - "multiple"
	Mode     string `yaml:"mode,omitempty" json:"mode,omitempty" jsonschema:"title=mode of rule,description=Mode of request rule to fuzz,enum=single,enum=multiple"`
	modeType modeType

	// description: |
	//   Keys is the optional list of key named parameters to fuzz.
	// examples:
	//   - name: Examples of keys
	//     value: >
	//       []string{"url", "file", "host"}
	Keys    []string `yaml:"keys,omitempty" json:"keys,omitempty" jsonschema:"title=keys of parameters to fuzz,description=Keys of parameters to fuzz"`
	keysMap map[string]struct{}
	// description: |
	//   KeysRegex is the optional list of regex key parameters to fuzz.
	// examples:
	//   - name: Examples of key regex
	//     value: >
	//       []string{"url.*"}
	KeysRegex []string `yaml:"keys-regex,omitempty" json:"keys-regex,omitempty" jsonschema:"title=keys regex to fuzz,description=Regex of parameter keys to fuzz"`
	keysRegex []*regexp.Regexp
	// description: |
	//   Values is the optional list of regex value parameters to fuzz.
	// examples:
	//   - name: Examples of value regex
	//     value: >
	//       []string{"https?://.*"}
	ValuesRegex []string `yaml:"values,omitempty" json:"values,omitempty" jsonschema:"title=values regex to fuzz,description=Regex of parameter values to fuzz"`
	valuesRegex []*regexp.Regexp

	// description: |
	//   Fuzz is the list of payloads to perform substitutions with.
	// examples:
	//   - name: Examples of fuzz
	//     value: >
	//       []string{"{{ssrf}}", "{{interactsh-url}}", "example-value"}
	Fuzz []string `yaml:"fuzz,omitempty" json:"fuzz,omitempty" jsonschema:"title=payloads of fuzz rule,description=Payloads to perform fuzzing substitutions with"`

	options   *protocols.ExecutorOptions
	generator *generators.PayloadGenerator
}

// ruleType is the type of rule enum declaration
type ruleType int

const (
	replaceRuleType ruleType = iota + 1
	prefixRuleType
	postfixRuleType
	infixRuleType
)

var stringToRuleType = map[string]ruleType{
	"replace": replaceRuleType,
	"prefix":  prefixRuleType,
	"postfix": postfixRuleType,
	"infix":   infixRuleType,
}

// partType is the part of rule enum declaration
type partType int

const (
	queryPartType partType = iota + 1
)

var stringToPartType = map[string]partType{
	"query": queryPartType,
}

// modeType is the mode of rule enum declaration
type modeType int

const (
	singleModeType modeType = iota + 1
	multipleModeType
)

var stringToModeType = map[string]modeType{
	"single":   singleModeType,
	"multiple": multipleModeType,
}

// matchKeyOrValue matches key value parameters with rule parameters
func (rule *Rule) matchKeyOrValue(key, value string) bool {
	if len(rule.keysMap) == 0 && len(rule.valuesRegex) == 0 && len(rule.keysRegex) == 0 {
		return true
	}
	if value != "" {
		for _, regex := range rule.valuesRegex {
			if regex.MatchString(value) {
				return true
			}
		}
	}
	if (len(rule.keysMap) > 0 || len(rule.keysRegex) > 0) && key != "" {
		if _, ok := rule.keysMap[strings.ToLower(key)]; ok {
			return true
		}
		for _, regex := range rule.keysRegex {
			if regex.MatchString(key) {
				return true
			}
		}
	}
	return false
}
