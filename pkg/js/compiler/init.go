package compiler

import "github.com/projectdiscovery/nuclei/v3/pkg/types"

// jsprotocolInit

var (
	// Per Execution Javascript timeout in seconds
	JsProtocolTimeout = 10
)

// Init initializes the javascript protocol
func Init(opts *types.Options) error {
	if opts.Timeout < 10 {
		// keep existing 10s timeout
		return nil
	}
	JsProtocolTimeout = opts.Timeout
	return nil
}
