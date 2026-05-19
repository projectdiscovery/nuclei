package compiler

import (
	"context"
	"errors"
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
	// When the runtime is abandoned (an orphan goroutine outlived the
	// interrupt grace period) ownership of the concurrency slot is
	// transferred to a reaper inside executeWithRuntime which calls
	// ephemeraljsc.Done after the orphan goroutine eventually exits;
	// releasing the slot eagerly would let stuck callbacks bypass
	// NonPoolingVMConcurrency.
	slotOwnedByReaper := false
	defer func() {
		if !slotOwnedByReaper {
			ephemeraljsc.Done()
		}
	}()

	runtime := createNewRuntime()
	val, runErr := executeWithRuntime(ctx, runtime, p, args, opts, ephemeraljsc.Done)
	if errors.Is(runErr, errRuntimeTerminationTimeout) {
		slotOwnedByReaper = true
	}
	return val, runErr
}
