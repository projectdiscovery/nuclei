package encoding

import (
	"fmt"

	"github.com/pkg/errors"
)

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

// Decoded is a decoded string for fuzzer
type Decoded struct {
	// Data is the decoded data
	Data string `json:"data"`
	// Encoders is a list of encoders used during decoding
	Encoders []string `json:"encoders"`
}

// Encode encodes the data using the encoders
// used during initial decoding and return
// the encoded data
func (d *Decoded) Encode(data string) string {
	// iterate through encoders in reverse order
	// to encode the data
	for i := len(d.Encoders) - 1; i >= 0; i-- {
		encoder := d.Encoders[i]
		data = encoders[encoder].Encode(data)
	}
	return data
}

// Decode decodes the data using the encoders
func Decode(data string) (*Decoded, error) {
	decoded, err := recursivelyDecode(&Decoded{Data: data})
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func recursivelyDecode(data *Decoded) (*Decoded, error) {
	for _, encoder := range encoders {
		if encoder.IsType(data.Data) {
			decoded, err := encoder.Decode(data.Data)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to decode data for %s", encoder.Name()))
			}
			data.Data = decoded
			data.Encoders = append(data.Encoders, encoder.Name())
			return recursivelyDecode(data)
		}
	}
	return data, nil // return the data if it doesn't seem to match any known encoding
}
