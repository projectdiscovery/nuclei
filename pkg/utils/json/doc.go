// Package json provides fast JSON encoding and decoding functionality.
//
// On supported platforms; Linux, Darwin, or Windows on amd64, or on arm64 with
// Go >= 1.20 and <= 1.23, the package uses the high-performance [sonic] library.
// On any other systems, it gracefully falls back to using the [go-json]
// implementation.
//
// This package acts as a wrapper around the underlying JSON APIs, offering
// standard operations such as marshaling, unmarshaling, and working with JSON
// encoders/decoders. It maintains compatibility with the standard encoding/json
// interfaces while delivering improved performance when possible.
//
// Additionally, it defines the customary [Marshaler] and [Unmarshaler]
// interfaces to facilitate custom JSON encoding and decoding implementations.
//
// TODO(dwisiswant0): This package should be moved to the
// [github.com/projectdiscovery/utils/json], but let see how it goes first.
package json
