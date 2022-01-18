package http

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// HTTPMethodType is the type of the method specified
type HTTPMethodType int

// name:HTTPMethodType
const (
	// name:GET
	HTTPGet HTTPMethodType = iota + 1
	// name:GET
	HTTPHead
	// name:POST
	HTTPPost
	// name:PUT
	HTTPPut
	// name:DELETE
	HTTPDelete
	// name:CONNECT
	HTTPConnect
	// name:OPTIONS
	HTTPOptions
	// name:TRACE
	HTTPTrace
	// name:PATCH
	HTTPPatch
	// name:PURGE
	HTTPPurge
	// name:Debug
	HTTPDebug
	limit
)

// HTTPMethodMapping is a table for conversion of method from string.
var HTTPMethodMapping = map[HTTPMethodType]string{
	HTTPGet:     "GET",
	HTTPHead:    "HEAD",
	HTTPPost:    "POST",
	HTTPPut:     "PUT",
	HTTPDelete:  "DELETE",
	HTTPConnect: "CONNECT",
	HTTPOptions: "OPTIONS",
	HTTPTrace:   "TRACE",
	HTTPPatch:   "PATCH",
	HTTPPurge:   "PURGE",
	HTTPDebug:   "DEBUG",
}

// GetSupportedHTTPMethodTypes returns list of supported types
func GetSupportedHTTPMethodTypes() []HTTPMethodType {
	var result []HTTPMethodType
	for index := HTTPMethodType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toHTTPMethodTypes(valueToMap string) (HTTPMethodType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range HTTPMethodMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid HTTP method verb: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToUpper(value))
}

func (t HTTPMethodType) String() string {
	return HTTPMethodMapping[t]
}

// HTTPMethodTypeHolder is used to hold internal type of the HTTP Method
type HTTPMethodTypeHolder struct {
	MethodType HTTPMethodType `mapping:"true"`
}

func (holder HTTPMethodTypeHolder) String() string {
	return holder.MethodType.String()
}

func (holder HTTPMethodTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "method is the HTTP request method",
		Description: "Method is the HTTP Request Method,enum=GET,enum=HEAD,enum=POST,enum=PUT,enum=DELETE,enum=CONNECT,enum=OPTIONS,enum=TRACE,enum=PATCH,enum=PURGE,enum=DEBUG",
	}
	for _, types := range GetSupportedHTTPMethodTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *HTTPMethodTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toHTTPMethodTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MethodType = computedType
	return nil
}

func (holder *HTTPMethodTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MethodType.String())
}

func (holder HTTPMethodTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MethodType.String(), nil
}
