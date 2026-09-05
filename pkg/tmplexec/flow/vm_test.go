package flow_test

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestGetJSRuntimeHonoursContext covers what made a saturated pool fatal rather than slow.
//
// The pool is shared by every scan in the process, and a runtime stays checked out for the
// whole flow, including any wait on the rate limiter. Once it is saturated, an acquire that
// ignored the context left a scan that had already been cancelled queueing for a runtime it
// only needed in order to unwind, unable to leave until an unrelated scan finished.
func TestGetJSRuntimeHonoursContext(t *testing.T) {
	opts := &types.Options{JsConcurrency: 100}

	runtime, err := flow.GetJSRuntime(context.Background(), opts)
	require.NoError(t, err, "a live scan still gets a runtime")
	flow.PutJSRuntime(runtime, true)

	// Acquire reports a cancelled context before it looks at whether a slot is free, so this
	// holds whether the pool is saturated or idle.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = flow.GetJSRuntime(ctx, opts)
	require.Error(t, err, "a cancelled scan must not queue for a runtime it will never use")
}

func TestGetJSRuntimeUnblocksCancelledAcquireWhenPoolIsFull(t *testing.T) {
	opts := &types.Options{JsConcurrency: 100}
	held := make([]*goja.Runtime, 0, 100)
	t.Cleanup(func() {
		for _, runtime := range held {
			flow.PutJSRuntime(runtime, true)
		}
	})
	for i := 0; i < 100; i++ {
		runtime, err := flow.GetJSRuntime(context.Background(), opts)
		require.NoError(t, err)
		held = append(held, runtime)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := flow.GetJSRuntime(ctx, opts)
	require.Error(t, err)
	require.Less(t, time.Since(start), 200*time.Millisecond)
}
