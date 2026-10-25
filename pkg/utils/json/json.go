// sonic compiles its fast paths only for the Go versions it has adopted, and
// prints a warning from init on any other toolchain before falling back to
// encoding/json. Mirroring its constraint here keeps that fallback silent: on a
// Go version sonic does not support we never link it and use encoding/json
// directly. Raise the upper bound when sonic adds support for a new Go version.
//go:build !gofuzz && (linux || darwin || windows) && (amd64 || arm64) && go1.17 && !go1.28

package json

import "github.com/bytedance/sonic"

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

// SetConfig sets the configuration for the JSON package.
func SetConfig(config *sonic.Config) {
	api = config.Froze()
}
