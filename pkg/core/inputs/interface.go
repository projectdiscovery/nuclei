package inputs

import "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"

// InputProvider is an input providing interface for the nuclei execution
// all input/target providers must implement this interface.
type InputProvider interface {
	// Count returns the number of items for input provider
	Count() int64
	// Scan iterates the input and each found item is passed to the
	// callback consumer.
	Scan(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
}
