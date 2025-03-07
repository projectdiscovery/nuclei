//go:build go1.24 || !(linux || darwin || windows) || !(amd64 || arm64)
// +build go1.24 !linux,!darwin,!windows !amd64,!arm64

package json

import "github.com/goccy/go-json"

// Exported functions from the [json] package.
var (
	Marshal       = json.Marshal
	Unmarshal     = json.Unmarshal
	MarshalIndent = json.MarshalIndent
	NewDecoder    = json.NewDecoder
	NewEncoder    = json.NewEncoder
)

// Encoder is a JSON encoder.
type Encoder = json.Encoder

// Decoder is a JSON decoder.
type Decoder = json.Decoder
