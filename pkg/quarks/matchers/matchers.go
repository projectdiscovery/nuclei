package matchers

// Matcher is a matcher structure parsed from a yaml file
type Matcher struct{}

// CompiledMatcher is the compiled matcher parsed from yaml file.
type CompiledMatcher struct{}

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
