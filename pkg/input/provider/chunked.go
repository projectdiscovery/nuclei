package provider

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// TODO: Implement ChunkedInputProvider
// 1. Lazy loading of input targets
// 2. Load and execute in chunks that fit in memory
// 3. Eliminate use of HybridMap since it performs worst due to marshal/unmarshal overhead

// ChunkedInputProvider is an input providing chunked targets instead of loading all at once
type ChunkedInputProvider interface {
	// Count returns total targets for input provider
	Count() int64
	// Iterate over all inputs in order
	Iterate(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
	// SetWithProbe adds item to input provider with http probing
	SetWithProbe(value string, probe types.InputLivenessProbe) error
	// SetWithExclusions adds item to input provider if it doesn't match any of the exclusions
	SetWithExclusions(value string) error
	// InputType returns the type of input provider
	InputType() string
	// Switches to the next chunk/batch of input
	NextChunk() bool
}
