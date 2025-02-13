package json

import "errors"

// Message is a raw encoded JSON value.
// It implements [Marshaler] and [Unmarshaler] and can
// be used to delay JSON decoding or precompute a JSON encoding.
//
// Copied from: https://cs.opensource.google/go/go/+/refs/tags/go1.23.6:src/encoding/json/stream.go;l=256-276
type Message []byte

// MarshalJSON returns m as the JSON encoding of m.
//
// Copied from: https://cs.opensource.google/go/go/+/refs/tags/go1.23.6:src/encoding/json/stream.go;l=256-276
func (m Message) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return m, nil
}

// UnmarshalJSON sets *m to a copy of data.
//
// Copied from: https://cs.opensource.google/go/go/+/refs/tags/go1.23.6:src/encoding/json/stream.go;l=256-276
func (m *Message) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("json.Message: UnmarshalJSON on nil pointer")
	}
	*m = append((*m)[0:0], data...)
	return nil
}
