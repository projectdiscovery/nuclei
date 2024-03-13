package dataformat

type Raw struct{}

var (
	_ DataFormat = &Raw{}
)

// NewRaw returns a new Raw encoder
func NewRaw() *Raw {
	return &Raw{}
}

// IsType returns true if the data is Raw encoded
func (r *Raw) IsType(data string) bool {
	return false
}

// Encode encodes the data into Raw format
func (r *Raw) Encode(data map[string]interface{}) (string, error) {
	return data["value"].(string), nil
}

// Decode decodes the data from Raw format
func (r *Raw) Decode(data string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"value": data,
	}, nil
}

// Name returns the name of the encoder
func (r *Raw) Name() string {
	return RawDataFormat
}
