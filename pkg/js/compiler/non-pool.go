package compiler

import (
	"sync"

	"github.com/dop251/goja"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var (
	ephemeraljsc    *syncutil.AdaptiveWaitGroup
	lazyFixedSgInit = sync.OnceFunc(func() {
		ephemeraljsc, _ = syncutil.New(syncutil.WithSize(NonPoolingVMConcurrency))
	})
)

func executeWithoutPooling(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	lazyFixedSgInit()
	ephemeraljsc.Add()
	defer ephemeraljsc.Done()
	runtime := createNewRuntime()
	return executeWithRuntime(runtime, p, args, opts)
}
