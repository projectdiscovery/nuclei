package dataformat

import (
	"errors"
	"fmt"
)

// dataformats is a list of dataformats
var dataformats map[string]DataFormat

const (
	// DefaultKey is the key i.e used when given
	// data is not of k-v type
	DefaultKey = "value"
)

func init() {
	dataformats = make(map[string]DataFormat)

	// register the default data formats
	RegisterDataFormat(NewGraphql())
	RegisterDataFormat(NewJSON())
	RegisterDataFormat(NewXML())
	RegisterDataFormat(NewRaw())
	RegisterDataFormat(NewForm())
	RegisterDataFormat(NewMultiPartForm())
}

const (
	// GraphqlDataFormat is the name of the GraphQL-over-HTTP JSON data format
	GraphqlDataFormat = "graphql"
	// JSONDataFormat is the name of the JSON data format
	JSONDataFormat = "json"
	// XMLDataFormat is the name of the XML data format
	XMLDataFormat = "xml"
	// RawDataFormat is the name of the Raw data format
	RawDataFormat = "raw"
	// FormDataFormat is the name of the Form data format
	FormDataFormat = "form"
	// MultiPartFormDataFormat is the name of the MultiPartForm data format
	MultiPartFormDataFormat = "multipart/form-data"
)

// decodePriority prefers more specific formats before generic ones (GraphQL
// bodies are valid JSON, so GraphQL must win over JSON).
var decodePriority = []string{
	GraphqlDataFormat,
	JSONDataFormat,
	XMLDataFormat,
	MultiPartFormDataFormat,
	FormDataFormat,
	RawDataFormat,
}

// Get returns the dataformat by name
func Get(name string) DataFormat {
	return dataformats[name]
}

// RegisterEncoder registers an encoder
func RegisterDataFormat(dataformat DataFormat) {
	dataformats[dataformat.Name()] = dataformat
}

// DataFormat is an interface for encoding and decoding
type DataFormat interface {
	// IsType returns true if the data is of the type
	IsType(data string) bool
	// Name returns the name of the encoder
	Name() string
	// Encode encodes the data into a format
	Encode(data KV) (string, error)
	// Decode decodes the data from a format
	Decode(input string) (KV, error)
}

// Decoded is a decoded data format
type Decoded struct {
	// DataFormat is the data format
	DataFormat string
	// Data is the decoded data
	Data KV
}

// Decode decodes the data from a format
func Decode(data string) (*Decoded, error) {
	tryDecode := func(dataformat DataFormat) (*Decoded, error) {
		if dataformat == nil || !dataformat.IsType(data) {
			return nil, nil
		}
		decoded, err := dataformat.Decode(data)
		if err != nil {
			return nil, err
		}
		return &Decoded{
			DataFormat: dataformat.Name(),
			Data:       decoded,
		}, nil
	}

	for _, name := range decodePriority {
		decoded, err := tryDecode(dataformats[name])
		if err != nil {
			return nil, err
		}
		if decoded != nil {
			return decoded, nil
		}
	}
	for name, dataformat := range dataformats {
		if containsString(decodePriority, name) {
			continue
		}
		decoded, err := tryDecode(dataformat)
		if err != nil {
			return nil, err
		}
		if decoded != nil {
			return decoded, nil
		}
	}
	return nil, nil
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// Encode encodes the data into a format
func Encode(data KV, dataformat string) (string, error) {
	if dataformat == "" {
		return "", errors.New("dataformat is required")
	}
	if encoder, ok := dataformats[dataformat]; ok {
		return encoder.Encode(data)
	}
	return "", fmt.Errorf("dataformat %s is not supported", dataformat)
}
