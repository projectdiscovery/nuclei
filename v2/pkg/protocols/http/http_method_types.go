package http

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// HttpMethodType is the type of the method specified
type HttpMethodType int

const (
	HttpGet HttpMethodType = iota + 1
	HttpHead
	HttpPost
	HttpPut
	HttpDelete
	HttpConnect
	HttpOptions
	HttpTrace
	HttpPatch
	HttpPurge
	//limit
	limit
)

// httpMethodMapping is a table for conversion of method from string.
var httpMethodMapping = map[HttpMethodType]string{
	HttpGet:     "GET",
	HttpHead:    "HEAD",
	HttpPost:    "POST",
	HttpPut:     "PUT",
	HttpDelete:  "DELETE",
	HttpConnect: "CONNECT",
	HttpOptions: "OPTIONS",
	HttpTrace:   "TRACE",
	HttpPatch:   "PATCH",
	HttpPurge:   "PURGE",
}

// GetSupportedHttpMethodTypes returns list of supported types
func GetSupportedHttpMethodTypes() []HttpMethodType {
	var result []HttpMethodType
	for index := HttpMethodType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toHttpMethodTypes(valueToMap string) (HttpMethodType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range httpMethodMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid http method verb: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToUpper(value))
}

func (t HttpMethodType) String() string {
	return httpMethodMapping[t]
}

// HttpMethodTypeHolder is used to hold internal type of the Http Method
type HttpMethodTypeHolder struct {
	MethodType HttpMethodType
}

func (holder HttpMethodTypeHolder) String() string {
	return holder.MethodType.String()
}

func (holder HttpMethodTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "method is the http request method",
		Description: "Method is the HTTP Request Method,enum=GET,enum=HEAD,enum=POST,enum=PUT,enum=DELETE,enum=CONNECT,enum=OPTIONS,enum=TRACE,enum=PATCH,enum=PURGE",
	}
	for _, types := range GetSupportedHttpMethodTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *HttpMethodTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toHttpMethodTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MethodType = computedType
	return nil
}

func (holder *HttpMethodTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MethodType.String())
}

func (holder HttpMethodTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MethodType.String(), nil
}
