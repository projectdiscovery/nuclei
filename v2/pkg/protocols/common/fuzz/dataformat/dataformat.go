package dataformat

// dataformats is a list of dataformats
var dataformats map[string]DataFormat

func init() {
	dataformats = make(map[string]DataFormat)

	// register the default data formats
	RegisterDataFormat(NewJSON())
	RegisterDataFormat(NewXML())
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
	Encode(map[string]interface{}) ([]byte, error)
	// Decode decodes the data from a format
	Decode([]byte) (map[string]interface{}, error)
}
