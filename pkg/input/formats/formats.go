package formats

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
)

// ParseReqRespCallback is a callback function for discovered raw requests
type ParseReqRespCallback func(rr *types.RequestResponse) bool

// InputFormatOptions contains options for the input
// this can be variables that can be passed or
// overrides or some other options
type InputFormatOptions struct {
	// Variables is list of variables that can be used
	// while generating requests in given format
	Variables map[string]interface{}
	// SkipFormatValidation is used to skip format validation
	// while debugging or testing if format is invalid then
	// requests are skipped instead of creating invalid requests
	SkipFormatValidation bool
	// RequiredOnly only uses required fields when generating requests
	// instead of all fields
	RequiredOnly bool
}

// Format is an interface implemented by all input formats
type Format interface {
	// Name returns the name of the format
	Name() string
	// Parse parses the input and calls the provided callback
	// function for each RawRequest it discovers.
	Parse(input string, resultsCb ParseReqRespCallback) error
	// SetOptions sets the options for the input format
	SetOptions(options InputFormatOptions)
}
