package swagger

import (
	"encoding/json"
	"os"
	"path"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats/openapi"
)

// SwaggerFormat is a Swagger Schema File parser
type SwaggerFormat struct{}

// New creates a new Swagger format parser
func New() *SwaggerFormat {
	return &SwaggerFormat{}
}

var _ formats.Format = &SwaggerFormat{}

// Name returns the name of the format
func (j *SwaggerFormat) Name() string {
	return "swagger"
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *SwaggerFormat) Parse(input string, resultsCb formats.RawRequestCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open data file")
	}
	defer file.Close()

	schemav2 := &openapi2.T{}
	ext := path.Ext(input)

	if ext == ".yaml" || ext == ".yml" {
		err = yaml.NewDecoder(file).Decode(schemav2)
	} else {
		err = json.NewDecoder(file).Decode(schemav2)
	}
	if err != nil {
		return errors.Wrap(err, "could not decode openapi 2.0 schema")
	}
	schema, err := openapi2conv.ToV3(schemav2)
	if err != nil {
		return errors.Wrap(err, "could not convert openapi 2.0 schema to 3.0")
	}
	loader := openapi3.NewLoader()
	err = loader.ResolveRefsIn(schema, nil)
	if err != nil {
		return errors.Wrap(err, "could not resolve openapi schema references")
	}
	openapi.GenerateRequestsFromSchema(schema, resultsCb)
	return nil
}
