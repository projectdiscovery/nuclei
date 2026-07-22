package swagger

import (
	"fmt"
	"io"
	"path"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/openapi"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"gopkg.in/yaml.v3"
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
		err = decodeYAML(data, schemav2)
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

func decodeYAML(data []byte, target interface{}) error {
	var value interface{}
	if err := yaml.Unmarshal(data, &value); err != nil {
		return err
	}

	jsonData, err := json.Marshal(normalizeYAMLValue(value))
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonData, target)
}

func normalizeYAMLValue(value interface{}) interface{} {
	switch value := value.(type) {
	case map[interface{}]interface{}:
		normalized := make(map[string]interface{}, len(value))
		for key, item := range value {
			normalized[fmt.Sprint(key)] = normalizeYAMLValue(item)
		}
		return normalized
	case map[string]interface{}:
		normalized := make(map[string]interface{}, len(value))
		for key, item := range value {
			normalized[key] = normalizeYAMLValue(item)
		}
		return normalized
	case []interface{}:
		for i, item := range value {
			value[i] = normalizeYAMLValue(item)
		}
	}
	return value
}
