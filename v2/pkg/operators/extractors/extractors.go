package extractors

import (
	"regexp"

	"github.com/itchyny/gojq"
)

// Extractor is used to extract part of response using a regex.
type Extractor struct {
	// Name is the extractor's name
	Name string `yaml:"name,omitempty"`
	// Type is the type of the extractor
	Type string `yaml:"type"`
	// extractorType is the internal type of the extractor
	extractorType ExtractorType

	// Regex are the regex pattern required to be present in the response
	Regex []string `yaml:"regex"`
	// RegexGroup specifies a group to extract from the regex
	RegexGroup int `yaml:"group"`
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp

	// KVal are the kval to be present in the response headers/cookies
	KVal []string `yaml:"kval,omitempty"`

	// XPath are the Xpath selectors for the extractor
	XPath []string `yaml:"xpath"`
	// Attribute is an optional attribute to extract from response XPath
	Attribute string `yaml:"attribute"`
	// JSON are the json pattern required to be present in the response
	JSON []string `yaml:"json"`
	// jsonCompiled is the compiled variant
	jsonCompiled []*gojq.Code

	// Part is the part of the request to match
	//
	// By default, matching is performed in request body.
	Part string `yaml:"part,omitempty"`
	// Internal defines if this is used internally
	Internal bool `yaml:"internal,omitempty"`
	// Global defines if this should be available globally
	Global bool `yaml:"global,omitempty"`
}

// ExtractorType is the type of the extractor specified
type ExtractorType = int

const (
	// RegexExtractor extracts responses with regexes
	RegexExtractor ExtractorType = iota + 1
	// KValExtractor extracts responses with key:value
	KValExtractor
	// XPathExtractor extracts responses with Xpath selectors
	XPathExtractor
	// JSONExtractor extracts responses with json
	JSONExtractor
)

// ExtractorTypes is an table for conversion of extractor type from string.
var ExtractorTypes = map[string]ExtractorType{
	"regex": RegexExtractor,
	"kval":  KValExtractor,
	"xpath": XPathExtractor,
	"json":  JSONExtractor,
}

// GetType returns the type of the matcher
func (e *Extractor) GetType() ExtractorType {
	return e.extractorType
}
