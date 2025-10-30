//go:build (linux || darwin || windows) && (amd64 || arm64)

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
