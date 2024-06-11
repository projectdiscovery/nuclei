package compiler

import (
	"log"
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
	// Validate the provided timeout
	if opts.Timeout < 10 {
		log.Println("Provided timeout too low, using default 10s timeout")
		opts.Timeout = 10
	}
	
	// Validate the provided concurrency
	if opts.JsConcurrency < 100 {
		log.Println("Provided JS concurrency too low, setting to default 100")
		opts.JsConcurrency = 100
	}
	
	// Calculate and set the JsProtocolTimeout
	JsProtocolTimeout = int(float64(opts.Timeout) * JsTimeoutMultiplier)
	
	// Adjust PoolingJsVmConcurrency based on NonPoolingVMConcurrency
	PoolingJsVmConcurrency = opts.JsConcurrency - NonPoolingVMConcurrency
	if PoolingJsVmConcurrency < 0 {
		log.Println("Adjusted PoolingJsVmConcurrency to minimum value 0")
		PoolingJsVmConcurrency = 0
	}

	log.Printf("JS Protocol Timeout set to %d seconds\n", JsProtocolTimeout)
	log.Printf("Pooling JS VM Concurrency set to %d\n", PoolingJsVmConcurrency)
	log.Printf("Non-Pooling JS VM Concurrency set to %d\n", NonPoolingVMConcurrency)

	return nil
}
