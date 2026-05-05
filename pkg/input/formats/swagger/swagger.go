package swagger

import (
	"io"
	"path"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/invopop/yaml"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/openapi"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// SwaggerFormat is a Swagger Schema File parser
type SwaggerFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new Swagger format parser
func New() *SwaggerFormat {
	return &SwaggerFormat{}
}

var _ formats.Format = &SwaggerFormat{}

// Name returns the name of the format
func (j *SwaggerFormat) Name() string {
	return "swagger"
}

func (j *SwaggerFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *SwaggerFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	schemav2 := &openapi2.T{}
	ext := path.Ext(filePath)
	var err error
	if ext == ".yaml" || ext == ".yml" {
		var data []byte
		data, err = io.ReadAll(input)
		if err != nil {
			return errors.Wrap(err, "could not read data file")
		}
		err = yaml.Unmarshal(data, schemav2)
	} else {
		err = json.NewDecoder(input).Decode(schemav2)
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
	return openapi.GenerateRequestsFromSchema(schema, j.opts, resultsCb)
}
