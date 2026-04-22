package compiler

import (
	"context"
	"sync"

	"github.com/Mzack9999/goja"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var (
	ephemeraljsc    *syncutil.AdaptiveWaitGroup
	lazyFixedSgInit = sync.OnceFunc(func() {
		ephemeraljsc, _ = syncutil.New(syncutil.WithSize(NonPoolingVMConcurrency))
	})
)

func executeWithoutPooling(ctx context.Context, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	lazyFixedSgInit()
	// Acquire a pool slot, respecting the execution deadline. Returns
	// immediately if the context has already expired.
	if err := ephemeraljsc.AddWithContext(ctx); err != nil {
		return nil, err
	}
	defer ephemeraljsc.Done()

	runtime := createNewRuntime()
	return executeWithRuntime(ctx, runtime, p, args, opts)
}
