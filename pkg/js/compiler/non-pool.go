package compiler

import (
	"context"
	"sync"
	"sync/atomic"

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

	runtime := createNewRuntime()

	// Watchdog: release the pool slot if the deadline expires while the
	// goroutine is still running (zombie). See executeWithPoolingProgram
	// for the full explanation. The atomic.Bool guarantees exactly one
	// Done() call between the watchdog and the normal defer path.
	var slotReleased atomic.Bool
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			runtime.Interrupt(ctx.Err())
			if slotReleased.CompareAndSwap(false, true) {
				ephemeraljsc.Done()
			}
		case <-done:
			if slotReleased.CompareAndSwap(false, true) {
				ephemeraljsc.Done()
			}
		}
	}()
	defer close(done)

	return executeWithRuntime(ctx, runtime, p, args, opts)
}
