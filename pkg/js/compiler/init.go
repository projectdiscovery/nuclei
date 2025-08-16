package compiler

import (
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// jsprotocolInit

var (
	PoolingJsVmConcurrency  = 100
	NonPoolingVMConcurrency = 20
	m                       sync.Mutex
)

// Init initializes the javascript protocol
func Init(opts *types.Options) error {
	m.Lock()
	defer m.Unlock()

	if opts.JsConcurrency < 100 {
		// 100 is reasonable default
		opts.JsConcurrency = 100
	}
	PoolingJsVmConcurrency = opts.JsConcurrency
	PoolingJsVmConcurrency -= NonPoolingVMConcurrency
	return nil
}
