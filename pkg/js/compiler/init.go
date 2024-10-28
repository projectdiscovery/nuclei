package compiler

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// jsprotocolInit

var (
	PoolingJsVmConcurrency  = 100
	NonPoolingVMConcurrency = 20
)

// Init initializes the javascript protocol
func Init(opts *types.Options) error {

	if opts.JsConcurrency < 100 {
		// 100 is reasonable default
		opts.JsConcurrency = 100
	}
	PoolingJsVmConcurrency = opts.JsConcurrency
	PoolingJsVmConcurrency -= NonPoolingVMConcurrency
	return nil
}
