package matchers

import (
	"regexp"

	"github.com/Knetic/govaluate"
)

// Matcher is used to identify whether a template was successful.
type Matcher struct {
	// Type is the type of the matcher
	Type string `yaml:"type"`
	// matcherType is the internal type of the matcher
	matcherType MatcherType

	// Name is matcher Name to be displayed in result output.
	Name string `yaml:"name,omitempty"`
	// Status are the acceptable status codes for the response
	Status []int `yaml:"status,omitempty"`
	// Size is the acceptable size for the response
	Size []int `yaml:"size,omitempty"`
	// Words are the words required to be present in the response
	Words []string `yaml:"words,omitempty"`
	// Regex are the regex pattern required to be present in the response
	Regex []string `yaml:"regex,omitempty"`
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp
	// Binary are the binary characters required to be present in the response
	Binary []string `yaml:"binary,omitempty"`
	// DSL are the dsl queries
	DSL []string `yaml:"dsl,omitempty"`
	// dslCompiled is the compiled variant
	dslCompiled []*govaluate.EvaluableExpression

	// Condition is the optional condition between two matcher variables
	//
	// By default, the condition is assumed to be OR.
	Condition string `yaml:"condition,omitempty"`
	// condition is the condition of the matcher
	condition ConditionType

	// Part is the part of the request to match
	//
	// By default, matching is performed in request body.
	Part string `yaml:"part,omitempty"`
	// part is the part of the request to match
	part Part
}

// MatcherType is the type of the matcher specified
type MatcherType = int

const (
	// WordsMatcher matches responses with words
	WordsMatcher MatcherType = iota + 1
	// RegexMatcher matches responses with regexes
	RegexMatcher
	// BinaryMatcher matches responses with words
	BinaryMatcher
	// StatusMatcher matches responses with status codes
	StatusMatcher
	// SizeMatcher matches responses with response size
	SizeMatcher
	// DSLMatcher matches based upon dsl syntax
	DSLMatcher
)

// MatcherTypes is an table for conversion of matcher type from string.
var MatcherTypes = map[string]MatcherType{
	"status": StatusMatcher,
	"size":   SizeMatcher,
	"word":   WordsMatcher,
	"regex":  RegexMatcher,
	"binary": BinaryMatcher,
	"dsl":    DSLMatcher,
}

// ConditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// ConditionTypes is an table for conversion of condition type from string.
var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}

// Part is the part of the request to match
type Part int

const (
	// BodyPart matches body of the response.
	BodyPart Part = iota + 1
	// HeaderPart matches headers of the response.
	HeaderPart
	// AllPart matches both response body and headers of the response.
	AllPart
)

// PartTypes is an table for conversion of part type from string.
var PartTypes = map[string]Part{
	"body":   BodyPart,
	"header": HeaderPart,
	"all":    AllPart,
}

// GetPart returns the part of the matcher
func (m *Matcher) GetPart() Part {
	return m.part
}
