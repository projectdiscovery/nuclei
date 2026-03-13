package dataformat

import (
	"errors"
	"fmt"
)

// dataformats is a list of dataformat constructors
var dataformats map[string]func() DataFormat

const (
	// DefaultKey is the key i.e used when given
	// data is not of k-v type
	DefaultKey = "value"
)

func init() {
	dataformats = make(map[string]func() DataFormat)

	// register the default data formats
	RegisterDataFormat(func() DataFormat { return NewJSON() })
	RegisterDataFormat(func() DataFormat { return NewXML() })
	RegisterDataFormat(func() DataFormat { return NewRaw() })
	RegisterDataFormat(func() DataFormat { return NewForm() })
	RegisterDataFormat(func() DataFormat { return NewMultiPartForm() })
}

const (
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

// Get returns a new instance of the dataformat by name
func Get(name string) DataFormat {
	if constructor, ok := dataformats[name]; ok {
		return constructor()
	}
	return nil
}

// RegisterEncoder registers a dataformat constructor
func RegisterDataFormat(constructor func() DataFormat) {
	df := constructor()
	dataformats[df.Name()] = constructor
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
	for _, constructor := range dataformats {
		dataformat := constructor()
		if dataformat.IsType(data) {
			decoded, err := dataformat.Decode(data)
			if err != nil {
				return nil, err
			}
			value := &Decoded{
				DataFormat: dataformat.Name(),
				Data:       decoded,
			}
			return value, nil
		}
	}
	return nil, nil
}

// Encode encodes the data into a format
func Encode(data KV, dataformat string) (string, error) {
	if dataformat == "" {
		return "", errors.New("dataformat is required")
	}
	if constructor, ok := dataformats[dataformat]; ok {
		encoder := constructor()
		return encoder.Encode(data)
	}
	return "", fmt.Errorf("dataformat %s is not supported", dataformat)
}
