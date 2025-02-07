// Package json provides a fast JSON encoding & decoding using the [sonic].
//
// This package serves as a wrapper around the [sonic.API], offering standard
// JSON operations like marshaling, unmarshaling, and working with JSON
// encoders/decoders. It maintains compatibility with the standard encoding/json
// interfaces while providing better performance through the sonic implementation.
//
// It also defines the standard Marshaler and Unmarshaler interfaces for custom
// JSON encoding and decoding implementations.
//
// TODO(dwisiswant0): This package should be moved to the
// [github.com/projectdiscovery/utils/json], but let see how it goes first.
package json

import (
	"errors"

	"github.com/bytedance/sonic"
)

var api = sonic.ConfigStd

// Exported functions from the [sonic.API].
var (
	Marshal       = api.Marshal
	Unmarshal     = api.Unmarshal
	MarshalIndent = api.MarshalIndent
	NewDecoder    = api.NewDecoder
	NewEncoder    = api.NewEncoder
)

// Encoder is a JSON encoder.
type Encoder = sonic.Encoder

// Decoder is a JSON decoder.
type Decoder = sonic.Decoder

// Marshaler is the interface implemented by types that
// can marshal themselves into valid JSON.
type Marshaler interface {
	MarshalJSON() ([]byte, error)
}

// Unmarshaler is the interface implemented by types
// that can unmarshal a JSON description of themselves.
// The input can be assumed to be a valid encoding of
// a JSON value. UnmarshalJSON must copy the JSON data
// if it wishes to retain the data after returning.
//
// By convention, to approximate the behavior of [Unmarshal] itself,
// Unmarshalers implement UnmarshalJSON([]byte("null")) as a no-op.
type Unmarshaler interface {
	UnmarshalJSON([]byte) error
}

// JSONCodec is the interface implemented by types that can marshal and
// unmarshal themselves into valid JSON.
type JSONCodec interface {
	Marshaler
	Unmarshaler
}

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

// SetConfig sets the configuration for the JSON package.
func SetConfig(config *sonic.Config) {
	api = config.Froze()
}
