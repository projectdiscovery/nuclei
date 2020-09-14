package extractors

import "regexp"

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
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp

	// KVal are the kval to be present in the response headers/cookies
	KVal []string `yaml:"kval,omitempty"`

	// Part is the part of the request to match
	//
	// By default, matching is performed in request body.
	Part string `yaml:"part,omitempty"`
	// part is the part of the request to match
	part Part

	// Internal defines if this is used internally
	Internal bool `yaml:"internal,omitempty"`
}

// ExtractorType is the type of the extractor specified
type ExtractorType = int

const (
	// RegexExtractor extracts responses with regexes
	RegexExtractor ExtractorType = iota + 1
	// KValExtractor extracts responses with key:value
	KValExtractor
)

// ExtractorTypes is an table for conversion of extractor type from string.
var ExtractorTypes = map[string]ExtractorType{
	"regex": RegexExtractor,
	"kval":  KValExtractor,
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
func (e *Extractor) GetPart() Part {
	return e.part
}
