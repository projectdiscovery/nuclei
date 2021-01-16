package matchers

import (
	"regexp"

	"github.com/Knetic/govaluate"
)

// Matcher is used to match a part in the output from a protocol.
type Matcher struct {
	// Type is the type of the matcher
	Type string `yaml:"type"`
	// Condition is the optional condition between two matcher variables
	//
	// By default, the condition is assumed to be OR.
	Condition string `yaml:"condition,omitempty"`

	// Part is the part of the data to match
	Part string `yaml:"part,omitempty"`

	// Negative specifies if the match should be reversed
	// It will only match if the condition is not true.
	Negative bool `yaml:"negative,omitempty"`

	// Name is matcher Name
	Name string `yaml:"name,omitempty"`
	// Status are the acceptable status codes for the response
	Status []int `yaml:"status,omitempty"`
	// Size is the acceptable size for the response
	Size []int `yaml:"size,omitempty"`
	// Words are the words required to be present in the response
	Words []string `yaml:"words,omitempty"`
	// Regex are the regex pattern required to be present in the response
	Regex []string `yaml:"regex,omitempty"`
	// Binary are the binary characters required to be present in the response
	Binary []string `yaml:"binary,omitempty"`
	// DSL are the dsl queries
	DSL []string `yaml:"dsl,omitempty"`

	// cached data for the compiled matcher
	condition     ConditionType
	matcherType   MatcherType
	regexCompiled []*regexp.Regexp
	dslCompiled   []*govaluate.EvaluableExpression
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

// Result reverts the results of the match if the matcher is of type negative.
func (m *Matcher) Result(data bool) bool {
	if m.Negative {
		return !data
	}
	return data
}

// GetType returns the type of the matcher
func (m *Matcher) GetType() MatcherType {
	return m.matcherType
}
