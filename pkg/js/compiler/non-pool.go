package compiler

import (
	"context"
	"sync"

	"github.com/projectdiscovery/goja"
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
	// Bound admission separately so queue time does not consume execution time.
	queueCtx, cancelQueue := executionTimeout(ctx, opts)
	defer cancelQueue()
	if err := ephemeraljsc.AddWithContext(queueCtx); err != nil {
		return nil, err
	}

	cancelQueue()
	ctx, cancel := executionTimeout(ctx, opts)
	defer cancel()

	runtime := createNewRuntime()
	session := newSession(sessionConfig{
		ctx:                  ctx,
		runtime:              runtime,
		program:              p,
		args:                 args,
		opts:                 opts,
		releaseSlot:          ephemeraljsc.Done,
		releaseAbandonedSlot: ephemeraljsc.Done,
	})
	return session.run()
}
