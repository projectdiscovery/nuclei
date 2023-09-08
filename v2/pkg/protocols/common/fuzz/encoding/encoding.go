package encoding

// encoders is a list of encoders
var encoders map[string]Encoder

func init() {
	encoders = make(map[string]Encoder)

	// register the default encoders
	RegisterEncoder(NewBase64())
	RegisterEncoder(NewURL())
}

// RegisterEncoder registers an encoder
func RegisterEncoder(encoder Encoder) {
	encoders[encoder.Name()] = encoder
}

// Encoder is an interface for encoding and decoding
// data.
type Encoder interface {
	// IsType returns true if the data is of the type
	IsType(data string) bool
	// Name returns the name of the encoder
	Name() string
	// Encode encodes the data into a format
	Encode(data string) string
	// Decode decodes the data from a format
	Decode(data string) (string, error)
}
