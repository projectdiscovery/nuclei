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
	RegisterDataFormat(NewJSON())
	RegisterDataFormat(NewXML())
	RegisterDataFormat(NewRaw())
	RegisterDataFormat(NewForm())
	RegisterDataFormat(NewMultiPartForm())
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
	for _, dataformat := range dataformats {
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
	if encoder, ok := dataformats[dataformat]; ok {
		return encoder.Encode(data)
	}
	return "", fmt.Errorf("dataformat %s is not supported", dataformat)
}
