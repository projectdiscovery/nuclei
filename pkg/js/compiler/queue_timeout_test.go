package compiler

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/stretchr/testify/require"
)

// These tests replace global admission pools and must not run in parallel.
// Go suspends parallel package tests until these sequential tests finish.
func TestExecutionTimeoutAfterAdmission(t *testing.T) {
	lazySgInit()
	lazyFixedSgInit()
	oldPool, oldEphemeral := pooljsc, ephemeraljsc
	oldConcurrency := PoolingJsVmConcurrency
	t.Cleanup(func() {
		pooljsc, ephemeraljsc = oldPool, oldEphemeral
		PoolingJsVmConcurrency = oldConcurrency
	})
	PoolingJsVmConcurrency = 1

	for _, pooled := range []bool{true, false} {
		name := "non-pooled"
		if pooled {
			name = "pooled"
		}
		t.Run(name, func(t *testing.T) {
			pool, err := syncutil.New(syncutil.WithSize(1))
			require.NoError(t, err)
			if pooled {
				pooljsc = pool
			} else {
				ephemeraljsc = pool
			}

			execute := func(ctx context.Context, source string, budget time.Duration, callback func(*goja.Runtime) error) (ExecuteResult, error) {
				program, err := SourceAutoMode(source, false)
				require.NoError(t, err)
				return New().ExecuteWithOptions(ctx, program, nil, &ExecuteOptions{
					Source: &source, Callback: callback,
					TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: budget},
				})
			}
			quick := `var until = Date.now() + 150; while (Date.now() < until) {} "matched-evidence";`
			loop := `while (true) {}`
			if pooled {
				quick = `var until = Date.now() + 150; while (Date.now() < until) {} ExportAs("proof", "matched-evidence"); Export(true);`
				loop = `Export(true); while (true) {}`
			}

			if pooled {
				t.Run("admission-budget-includes-resize", func(t *testing.T) {
					occupied, err := syncutil.New(syncutil.WithSize(2))
					require.NoError(t, err)
					occupied.Add()
					occupied.Add()
					pooljsc = occupied
					defer func() {
						occupied.Done()
						occupied.Done()
						pooljsc = pool
					}()
					ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
					defer cancel()
					started := false
					begin := time.Now()
					_, err = execute(ctx, quick, 50*time.Millisecond, func(*goja.Runtime) error {
						started = true
						return nil
					})
					require.ErrorIs(t, err, context.DeadlineExceeded)
					require.False(t, started)
					require.Less(t, time.Since(begin), 250*time.Millisecond)
				})
			}

			t.Run("quick-script-after-queue", func(t *testing.T) {
				// The same script succeeds without contention.
				result, err := execute(t.Context(), quick, 300*time.Millisecond, nil)
				require.NoError(t, err)
				require.True(t, result.GetSuccess())

				pool.Add()
				released := make(chan struct{})
				timer := time.AfterFunc(200*time.Millisecond, func() {
					pool.Done()
					close(released)
				})
				defer func() {
					if timer.Stop() {
						pool.Done()
					} else {
						<-released
					}
				}()
				started := false
				begin := time.Now()
				result, err = execute(t.Context(), quick, 300*time.Millisecond, func(*goja.Runtime) error {
					started = true
					return nil
				})
				t.Logf("queue release=200ms, JS budget=300ms, elapsed=%s, started=%v, result=%v, error=%v", time.Since(begin), started, result, err)
				require.NoError(t, err)
				require.True(t, started)
				require.True(t, result.GetSuccess())
				if pooled {
					require.Equal(t, "matched-evidence", result["proof"])
				} else {
					require.Equal(t, "matched-evidence", result["response"])
				}
			})

			t.Run("caller-deadline-in-queue", func(t *testing.T) {
				pool.Add()
				defer pool.Done()
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				started := false
				_, err := execute(ctx, quick, time.Second, func(*goja.Runtime) error {
					started = true
					return nil
				})
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.False(t, started)
			})

			t.Run("caller-cancels-queued-execution", func(t *testing.T) {
				pool.Add()
				defer pool.Done()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				timer := time.AfterFunc(50*time.Millisecond, cancel)
				defer timer.Stop()
				started := false
				_, err := execute(ctx, quick, time.Second, func(*goja.Runtime) error {
					started = true
					return nil
				})
				require.ErrorIs(t, err, context.Canceled)
				require.False(t, started)
			})

			t.Run("admission-budget", func(t *testing.T) {
				pool.Add()
				defer pool.Done()
				started := false
				_, err := execute(t.Context(), quick, 50*time.Millisecond, func(*goja.Runtime) error {
					started = true
					return nil
				})
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.False(t, started)
			})

			t.Run("caller-deadline-during-execution", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				started := false
				_, err := execute(ctx, loop, time.Second, func(*goja.Runtime) error {
					started = true
					return nil
				})
				require.True(t, started)
				require.ErrorIs(t, err, context.DeadlineExceeded)
			})

			t.Run("nonpositive-budget", func(t *testing.T) {
				for _, budget := range []time.Duration{0, -time.Millisecond} {
					_, err := execute(t.Context(), quick, budget, nil)
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			})

			t.Run("execution-budget", func(t *testing.T) {
				_, err := execute(t.Context(), loop, 50*time.Millisecond, nil)
				require.ErrorIs(t, err, context.DeadlineExceeded)
			})
		})
	}
}

func TestExecuteProgramWithoutTimeoutVariants(t *testing.T) {
	for _, source := range []string{`true;`, `Export(true);`} {
		program, err := SourceAutoMode(source, false)
		require.NoError(t, err)
		value, err := ExecuteProgram(t.Context(), program, NewExecuteArgs(), &ExecuteOptions{Source: &source})
		require.NoError(t, err)
		require.True(t, value.ToBoolean())
	}
}
