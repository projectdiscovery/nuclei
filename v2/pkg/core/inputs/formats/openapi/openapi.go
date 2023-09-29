package openapi

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
)

// OpenAPIFormat is a OpenAPI Schema File parser
type OpenAPIFormat struct{}

// New creates a new OpenAPI format parser
func New() *OpenAPIFormat {
	return &OpenAPIFormat{}
}

var _ formats.Format = &OpenAPIFormat{}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *OpenAPIFormat) Parse(input string, resultsCb formats.RawRequestCallback) error {
	loader := openapi3.NewLoader()
	schema, err := loader.LoadFromFile(input)
	if err != nil {
		return errors.Wrap(err, "could not decode openapi 3.0 schema")
	}
	GenerateRequestsFromSchema(schema, resultsCb)
	return nil
}
