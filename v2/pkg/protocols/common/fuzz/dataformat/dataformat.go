package dataformat

import (
	"errors"
	"fmt"
)

// dataformats is a list of dataformats
var dataformats map[string]DataFormat

func init() {
	dataformats = make(map[string]DataFormat)

	// register the default data formats
	RegisterDataFormat(NewJSON())
	RegisterDataFormat(NewXML())
	RegisterDataFormat(NewRaw())
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
	Encode(data map[string]interface{}) (string, error)
	// Decode decodes the data from a format
	Decode(input string) (map[string]interface{}, error)
}

// Decoded is a decoded data format
type Decoded struct {
	// DataFormat is the data format
	DataFormat string
	// Data is the decoded data
	Data map[string]interface{}
}

const rawDataFormat = "raw"

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
	decodedValue, err := dataformats[rawDataFormat].Decode(data)
	if err != nil {
		return nil, err
	}
	value := &Decoded{
		DataFormat: rawDataFormat,
		Data:       decodedValue,
	}
	return value, nil
}

// Encode encodes the data into a format
func Encode(data map[string]interface{}, dataformat string) (string, error) {
	if dataformat == "" {
		return "", errors.New("dataformat is required")
	}
	if encoder, ok := dataformats[dataformat]; ok {
		return encoder.Encode(data)
	}
	return "", fmt.Errorf("dataformat %s is not supported", dataformat)
}
