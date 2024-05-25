package compiler

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// jsprotocolInit

var (
	// Per Execution Javascript timeout in seconds
	JsProtocolTimeout       = 10
	PoolingJsVmConcurrency  = 100
	NonPoolingVMConcurrency = 20
	JsTimeoutMultiplier     = 1.5
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
	// we have dialer timeout set to 10s so js needs to be at least
	// 15s to return the actual error if not it will be a dialer timeout
	JsProtocolTimeout = int(float64(opts.Timeout) * JsTimeoutMultiplier)
	PoolingJsVmConcurrency = opts.JsConcurrency
	PoolingJsVmConcurrency -= NonPoolingVMConcurrency
	return nil
}
