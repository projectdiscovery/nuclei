//go:build !((linux && amd64) || (linux && arm64 && go1.20) || (windows && amd64) || (windows && arm64 && go1.20) || (darwin && amd64) || (darwin && arm64 && go1.20))
// +build !linux !amd64
// +build !linux !arm64 !go1.20
// +build !windows !amd64
// +build !windows !arm64 !go1.20
// +build !darwin !amd64
// +build !darwin !arm64 !go1.20

package json

import "github.com/goccy/go-json"

// Exported functions from the [sonic.API].
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
