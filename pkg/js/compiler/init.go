package compiler

import "github.com/projectdiscovery/nuclei/v3/pkg/types"

// jsprotocolInit

var (
	// Per Execution Javascript timeout in seconds
	JsProtocolTimeout       = 10
	PoolingJsVmConcurrency  = 100
	NonPoolingVMConcurrency = 20
)

// Init initializes the javascript protocol
func Init(opts *types.Options) error {
	if opts.Timeout < 10 {
		// keep existing 10s timeout
		return nil
	}
	if opts.JsConcurrency < 100 {
		// 100 is reasonable default
		opts.JsConcurrency = 100
	}
	JsProtocolTimeout = opts.Timeout
	PoolingJsVmConcurrency = opts.JsConcurrency
	PoolingJsVmConcurrency -= NonPoolingVMConcurrency
	return nil
}
