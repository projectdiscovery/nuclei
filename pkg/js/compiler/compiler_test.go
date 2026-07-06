package compiler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNewCompilerConsoleDebug(t *testing.T) {
	gotString := ""
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	gologger.DefaultLogger.SetWriter(&noopWriter{
		Callback: func(data []byte, level levels.Level) {
			gotString = string(data)
		},
	})

	compiler := New()
	p, err := SourceAutoMode("console.log('hello world');", false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = compiler.ExecuteWithOptions(t.Context(), p, NewExecuteArgs(), &ExecuteOptions{
		TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: time.Duration(20) * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotString, "hello world") {
		t.Fatalf("console.log not working, got=%v", gotString)
	}
}

func TestRequireLocalFileAccessDenied(t *testing.T) {
	modulePath := writeModuleFile(t, t.TempDir(), "outside.js", `module.exports = { value: "outside-secret" };`)
	script := fmt.Sprintf(`var helper = require(%q); ExportAs("value", helper.value); true;`, modulePath)

	result, err := executeScript(t, t.Name(), false, script)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-lfa is not enabled")
	require.Equal(t, err.Error(), result["error"])
}

func TestRequireTemplateModuleAllowedWithoutLFA(t *testing.T) {
	originalTemplatesDir := config.DefaultConfig.TemplatesDirectory
	templatesDir := t.TempDir()
	configuredTemplatesDir, moduleBaseDir := templateDirAlias(t, templatesDir)
	config.DefaultConfig.SetTemplatesDir(configuredTemplatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(originalTemplatesDir)
	})

	modulePath := writeModuleFile(t, moduleBaseDir, filepath.Join("helpers", "allowed.js"), `module.exports = { value: "sandbox-ok" };`)
	script := fmt.Sprintf(`var helper = require(%q); ExportAs("value", helper.value); true;`, modulePath)

	result, err := executeScript(t, t.Name(), false, script)
	require.NoError(t, err)
	require.Equal(t, "sandbox-ok", result["value"])
}

func TestRequireLocalFileAccessAllowed(t *testing.T) {
	modulePath := writeModuleFile(t, t.TempDir(), "outside.js", `module.exports = { value: "outside-ok" };`)
	script := fmt.Sprintf(`var helper = require(%q); ExportAs("value", helper.value); true;`, modulePath)

	result, err := executeScript(t, t.Name(), true, script)
	require.NoError(t, err)
	require.Equal(t, "outside-ok", result["value"])
}

func TestRequireDoesNotReusePrivilegedModuleCacheAcrossExecutions(t *testing.T) {
	modulePath := writeModuleFile(t, t.TempDir(), "outside.js", `module.exports = { value: "outside-ok" };`)
	program, err := goja.Compile("", fmt.Sprintf(`require(%q).value`, modulePath), false)
	require.NoError(t, err)

	allowExecutionID := "allow-" + t.Name()
	denyExecutionID := "deny-" + t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: allowExecutionID, AllowLocalFileAccess: true})
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: denyExecutionID, AllowLocalFileAccess: false})

	runtime := createNewRuntime()
	firstValue, err := executeWithRuntime(t.Context(), runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: allowExecutionID,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "outside-ok", firstValue.Export())

	_, err = executeWithRuntime(t.Context(), runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: denyExecutionID,
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-lfa is not enabled")
}

func TestExecuteWithRuntimeCleansUpAfterCallbackPanic(t *testing.T) {
	program, err := goja.Compile("", `1`, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	args := NewExecuteArgs()
	args.Args["arg"] = "value"
	args.TemplateCtx["template-key"] = "template-value"

	cleanupCalled := false
	panicValue := "callback panic"

	func() {
		defer func() {
			require.Equal(t, panicValue, recover())
		}()

		_, _ = executeWithRuntime(t.Context(), runtime, program, args, &ExecuteOptions{
			ExecutionId: "callback-panic-cleanup",
			Callback: func(rt *goja.Runtime) error {
				require.NoError(t, rt.Set("callbackState", "partial"))
				panic(panicValue)
			},
			Cleanup: func(rt *goja.Runtime) {
				cleanupCalled = true
				_ = rt.GlobalObject().Delete("callbackState")
			},
		}, nil)
		t.Fatal("executeWithRuntime did not panic")
	}()

	require.True(t, cleanupCalled)
	require.Nil(t, runtime.Get("template"))
	require.Nil(t, runtime.Get("arg"))
	require.Nil(t, runtime.Get("callbackState"))

	_, ok := runtime.GetContextValue("executionId")
	require.False(t, ok)
	_, ok = runtime.GetContextValue("ctx")
	require.False(t, ok)
}

func TestExecuteWithRuntimeCallbackErrorCleansInitializedState(t *testing.T) {
	program, err := goja.Compile("", `1`, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	args := NewExecuteArgs()
	args.Args["arg"] = "value"
	args.TemplateCtx["marker"] = "template"

	cleanupCalled := false
	callbackErr := fmt.Errorf("callback setup failed")

	_, err = executeWithRuntime(t.Context(), runtime, program, args, &ExecuteOptions{
		ExecutionId: "callback-error-cleanup",
		Callback: func(rt *goja.Runtime) error {
			require.Equal(t, "value", rt.Get("arg").String())
			_, ok := rt.GetContextValue("ctx")
			require.True(t, ok)
			require.NoError(t, rt.Set("callbackState", "partial"))
			return callbackErr
		},
		Cleanup: func(rt *goja.Runtime) {
			cleanupCalled = true
			_ = rt.GlobalObject().Delete("callbackState")
		},
	}, nil)
	require.ErrorIs(t, err, callbackErr)
	require.True(t, cleanupCalled)
	require.Nil(t, runtime.Get("template"))
	require.Nil(t, runtime.Get("arg"))
	require.Nil(t, runtime.Get("callbackState"))

	_, ok := runtime.GetContextValue("executionId")
	require.False(t, ok)
	_, ok = runtime.GetContextValue("ctx")
	require.False(t, ok)
}

func TestExecuteWithRuntimePromptInterruptCleansAndAllowsReuse(t *testing.T) {
	program, err := goja.Compile("", `while (true) {}`, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	args := NewExecuteArgs()
	args.Args["arg"] = "value"
	args.TemplateCtx["marker"] = "template"

	cleanupCalled := false
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	_, err = executeWithRuntime(ctx, runtime, program, args, &ExecuteOptions{
		ExecutionId: "prompt-interrupt-cleanup",
		Cleanup: func(rt *goja.Runtime) {
			cleanupCalled = true
			_ = rt.GlobalObject().Delete("cleanupState")
		},
	}, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, errRuntimeTerminationTimeout)
	require.True(t, cleanupCalled)
	require.Nil(t, runtime.Get("template"))
	require.Nil(t, runtime.Get("arg"))

	_, ok := runtime.GetContextValue("executionId")
	require.False(t, ok)
	_, ok = runtime.GetContextValue("ctx")
	require.False(t, ok)

	reuseProgram, err := goja.Compile("", `typeof arg === "undefined" && template.marker === undefined`, false)
	require.NoError(t, err)
	value, err := executeWithRuntime(t.Context(), runtime, reuseProgram, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: "prompt-interrupt-reuse",
	}, nil)
	require.NoError(t, err)
	require.True(t, value.ToBoolean())
}

func TestNonPooledRuntimeTerminatesOnContextExpiry(t *testing.T) {
	timeout := 300 * time.Millisecond

	infiniteLoop := `while(true) {}`
	p, err := SourceAutoMode(infiniteLoop, false)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := executeWithoutPooling(ctx, p, NewExecuteArgs(), &ExecuteOptions{Source: &infiniteLoop})
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(timeout * 5):
		t.Fatal("runtime did not terminate after context expiry")
	}
}

func TestNonPooledNormalExecutionReleasesSlot(t *testing.T) {
	src := `1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	lazyFixedSgInit()
	initialCurrent := ephemeraljsc.Current()

	value, err := executeWithoutPooling(t.Context(), p, NewExecuteArgs(), &ExecuteOptions{Source: &src})
	require.NoError(t, err)
	require.Equal(t, int64(1), value.Export())
	require.Equal(t, initialCurrent, ephemeraljsc.Current())
}

func TestNonPooledRuntimeAbandonedWhenNativeCallbackStuck(t *testing.T) {
	src := `block(); 1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrphan := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOrphan)

	lazyFixedSgInit()
	initialCurrent := ephemeraljsc.Current()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	_, err = executeWithoutPooling(ctx, p, NewExecuteArgs(), &ExecuteOptions{
		Source: &src,
		Callback: func(rt *goja.Runtime) error {
			return rt.Set("block", func() {
				<-release
			})
		},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, errRuntimeTerminationTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.GreaterOrEqual(t, ephemeraljsc.Current(), initialCurrent+1,
		"abandoned non-pooled runtime must keep its concurrency slot while the orphan is still alive")

	releaseOrphan()

	require.Eventually(t, func() bool {
		return ephemeraljsc.Current() == initialCurrent
	}, 5*time.Second, 10*time.Millisecond, "non-pooled slot must be released once the orphan goroutine exits")
}

func TestPooledRuntimeTerminatesOnContextExpiry(t *testing.T) {
	timeout := 300 * time.Millisecond

	infiniteLoop := `while(true) {}`
	p, err := SourceAutoMode(infiniteLoop, false)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := executeWithPoolingProgram(ctx, p, NewExecuteArgs(), &ExecuteOptions{Source: &infiniteLoop})
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(timeout * 5):
		t.Fatal("runtime did not terminate after context expiry")
	}
}

func TestPooledRuntimeNormalExecutionCleansStateBeforeReuse(t *testing.T) {
	src := `Export("ok"); ExportAs("named", arg); true`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	useRuntimePool(t, runtime)

	lazySgInit()
	initialCurrent := pooljsc.Current()

	args := NewExecuteArgs()
	args.Args["arg"] = "value"
	args.TemplateCtx["marker"] = "template"

	cleanupCalled := false
	value, err := executeWithPoolingProgram(t.Context(), p, args, &ExecuteOptions{
		Source:      &src,
		ExecutionId: "pooled-cleanup",
		Callback: func(rt *goja.Runtime) error {
			require.NoError(t, rt.Set("callbackState", "temporary"))
			return nil
		},
		Cleanup: func(rt *goja.Runtime) {
			cleanupCalled = true
			_ = rt.GlobalObject().Delete("callbackState")
		},
	})
	require.NoError(t, err)
	require.Equal(t, "ok", value.Export())
	require.True(t, cleanupCalled)
	require.Equal(t, initialCurrent, pooljsc.Current())

	require.Nil(t, runtime.Get("template"))
	require.Nil(t, runtime.Get("arg"))
	require.Nil(t, runtime.Get("callbackState"))
	require.Nil(t, runtime.Get(exportToken))
	require.Nil(t, runtime.Get(exportAsToken))
	_, ok := runtime.GetContextValue("executionId")
	require.False(t, ok)
	_, ok = runtime.GetContextValue("ctx")
	require.False(t, ok)
}

func TestPooledCallbackErrorReleasesSlotAndCleansExportHelpers(t *testing.T) {
	src := `ExportAs("named", "value"); true`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	useRuntimePool(t, runtime)

	lazySgInit()
	initialCurrent := pooljsc.Current()
	callbackErr := fmt.Errorf("callback setup failed")

	_, err = executeWithPoolingProgram(t.Context(), p, NewExecuteArgs(), &ExecuteOptions{
		Source: &src,
		Callback: func(rt *goja.Runtime) error {
			require.NoError(t, rt.Set("callbackState", "temporary"))
			return callbackErr
		},
		Cleanup: func(rt *goja.Runtime) {
			_ = rt.GlobalObject().Delete("callbackState")
		},
	})
	require.ErrorIs(t, err, callbackErr)
	require.Equal(t, initialCurrent, pooljsc.Current())

	require.Nil(t, runtime.Get("callbackState"))
	require.Nil(t, runtime.Get(exportToken))
	require.Nil(t, runtime.Get(exportAsToken))
}

// TestPooledRuntimeAbandonedReleasesSlotOnlyAfterOrphanExits verifies that
// when a runtime is abandoned because its goja goroutine outlived the
// interrupt grace period, executeWithPoolingProgram does NOT release the
// concurrency slot eagerly. Releasing it eagerly would let a stream of
// stuck callbacks bypass PoolingJsVmConcurrency and trade the original
// map-race crash for unbounded resource growth. The slot must stay held
// by the reaper goroutine until the orphan goroutine actually exits.
func TestPooledRuntimeAbandonedReleasesSlotOnlyAfterOrphanExits(t *testing.T) {
	src := `ExportAs("k","v"); block(); 1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrphan := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOrphan)

	lazySgInit()
	initialCurrent := pooljsc.Current()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	_, err = executeWithPoolingProgram(ctx, p, NewExecuteArgs(), &ExecuteOptions{
		Source: &src,
		Callback: func(rt *goja.Runtime) error {
			return rt.Set("block", func() {
				<-release
			})
		},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, errRuntimeTerminationTimeout,
		"runtime should be flagged as abandoned when its goroutine outlives the interrupt grace period")

	require.GreaterOrEqual(t, pooljsc.Current(), initialCurrent+1,
		"abandoned runtime must keep its concurrency slot held by the reaper while the orphan is still alive")

	releaseOrphan()

	require.Eventually(t, func() bool {
		return pooljsc.Current() == initialCurrent
	}, 5*time.Second, 10*time.Millisecond, "concurrency slot must be released once the orphan goroutine exits")
}

// TestPooledRuntimeAbandonedWhenInterruptStuck reproduces the conditions
// of https://github.com/projectdiscovery/nuclei/issues/7376: a JS program
// is blocked inside a native Go call and ignores the goja Interrupt(), so
// the inner goroutine outlives the grace period after a context cancel.
// Before the fix, the runtime would still be returned to the sync.Pool and
// reused by the next caller, which would race with the orphan goroutine
// on goja's per-runtime maps and trigger a fatal "concurrent map read and
// map write" runtime panic. After the fix, executeWithPoolingProgram must
// return errRuntimeTerminationTimeout (still wrapping context.DeadlineExceeded
// for backwards compatibility) and abandon the runtime instead of pooling it.
func TestPooledRuntimeAbandonedWhenInterruptStuck(t *testing.T) {
	// A real script using ExportAs so executeWithPoolingProgram (not the
	// non-pooled fallback) is taken — see ExecuteProgram source-routing.
	src := `ExportAs("k", "v"); block(); 1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	// The native Go function blocks until release is closed. We close it
	// only after the test has observed the timeout error so the orphan
	// goroutine eventually unwinds and the abandoned runtime is GC-able.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	done := make(chan error, 1)
	go func() {
		_, err := executeWithPoolingProgram(ctx, p, NewExecuteArgs(), &ExecuteOptions{
			Source: &src,
			Callback: func(rt *goja.Runtime) error {
				return rt.Set("block", func() {
					<-release
				})
			},
		})
		done <- err
	}()

	// 100ms ctx + 1s goja interrupt grace period + slack
	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorIs(t, err, errRuntimeTerminationTimeout,
			"runtime should be flagged as abandoned when its goroutine outlives the interrupt grace period")
		require.ErrorIs(t, err, context.DeadlineExceeded,
			"the underlying context cancellation cause should still be reachable for callers using errors.Is")
	case <-time.After(5 * time.Second):
		t.Fatal("executeWithPoolingProgram did not return within the grace period")
	}
}

func TestSessionAbandonmentSkipsFinalizeCleanupAndNormalRelease(t *testing.T) {
	src := `block(); "done"`
	p, err := goja.Compile("", src, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	args := NewExecuteArgs()
	args.Args["arg"] = "value"

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrphan := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOrphan)

	abandonedSlotReleased := make(chan struct{})
	cleanupCalled := false
	pathCleanupCalled := false
	finalizeCalled := false
	returnCalled := false
	releaseCalled := false

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	session := newSession(sessionConfig{
		ctx:     ctx,
		runtime: runtime,
		program: p,
		args:    args,
		opts: &ExecuteOptions{
			Callback: func(rt *goja.Runtime) error {
				return rt.Set("block", func() {
					<-release
				})
			},
			Cleanup: func(rt *goja.Runtime) {
				cleanupCalled = true
			},
		},
		prepareRuntime: func(rt *goja.Runtime) error {
			return rt.Set("pathState", "temporary")
		},
		cleanupRuntime: func(rt *goja.Runtime) {
			pathCleanupCalled = true
		},
		finalizeResult: func(rt *goja.Runtime, val goja.Value) (goja.Value, error) {
			finalizeCalled = true
			return val, nil
		},
		returnRuntime: func(rt *goja.Runtime) {
			returnCalled = true
		},
		releaseSlot: func() {
			releaseCalled = true
		},
		releaseAbandonedSlot: func() {
			close(abandonedSlotReleased)
		},
	})

	_, err = session.run()
	require.ErrorIs(t, err, errRuntimeTerminationTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, cleanupCalled)
	require.False(t, pathCleanupCalled)
	require.False(t, finalizeCalled)
	require.False(t, returnCalled)
	require.False(t, releaseCalled)

	releaseOrphan()
	select {
	case <-abandonedSlotReleased:
	case <-time.After(5 * time.Second):
		t.Fatal("abandoned slot was not released after orphan exit")
	}
}

func TestPooledRuntimeAbandonmentSkipsCleanupAndRuntimeAccess(t *testing.T) {
	src := `ExportAs("before", "value"); block(); 1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	args := NewExecuteArgs()
	args.Args["arg"] = "value"
	args.TemplateCtx["marker"] = "template"

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrphan := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOrphan)

	report := make(chan []string, 1)
	cleanupCalled := false

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	_, err = executeWithPoolingProgram(ctx, p, args, &ExecuteOptions{
		Source: &src,
		Callback: func(rt *goja.Runtime) error {
			return rt.Set("block", func() {
				<-release
				template := rt.Get("template").ToObject(rt)
				exportType := "missing"
				if _, ok := goja.AssertFunction(rt.Get(exportToken)); ok {
					exportType = "function"
				}
				exportAsType := "missing"
				if _, ok := goja.AssertFunction(rt.Get(exportAsToken)); ok {
					exportAsType = "function"
				}
				report <- []string{
					exportType,
					exportAsType,
					template.Get("marker").String(),
					rt.Get("arg").String(),
				}
			})
		},
		Cleanup: func(rt *goja.Runtime) {
			cleanupCalled = true
		},
	})
	require.ErrorIs(t, err, errRuntimeTerminationTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, cleanupCalled, "caller cleanup must not touch an abandoned runtime")

	releaseOrphan()

	select {
	case got := <-report:
		require.Equal(t, []string{"function", "function", "template", "value"}, got)
	case <-time.After(5 * time.Second):
		t.Fatal("orphaned runtime did not report state after release")
	}
}

func TestPooledAbandonedRuntimeIsNotReused(t *testing.T) {
	src := `ExportAs("before", "value"); abandonedSentinel = "leaked"; block(); 1`
	p, err := SourceAutoMode(src, false)
	require.NoError(t, err)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrphan := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseOrphan)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	_, err = executeWithPoolingProgram(ctx, p, NewExecuteArgs(), &ExecuteOptions{
		Source: &src,
		Callback: func(rt *goja.Runtime) error {
			return rt.Set("block", func() {
				<-release
			})
		},
	})
	require.ErrorIs(t, err, errRuntimeTerminationTimeout)

	releaseOrphan()

	reuseSrc := `ExportAs("seen", typeof abandonedSentinel); true`
	reuseProgram, err := SourceAutoMode(reuseSrc, false)
	require.NoError(t, err)

	result, err := New().ExecuteWithOptions(t.Context(), reuseProgram, NewExecuteArgs(), &ExecuteOptions{
		Source: &reuseSrc,
		TimeoutVariants: &types.Timeouts{
			JsCompilerExecutionTimeout: 5 * time.Second,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "undefined", result["seen"])
}

func executeScript(t *testing.T, executionID string, allowLocalFileAccess bool, script string) (ExecuteResult, error) {
	t.Helper()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: allowLocalFileAccess})

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)

	compiler := New()
	return compiler.ExecuteWithOptions(t.Context(), compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: executionID,
		Source:      &script,
		TimeoutVariants: &types.Timeouts{
			JsCompilerExecutionTimeout: 5 * time.Second,
		},
	})
}

func writeModuleFile(t *testing.T, baseDir string, relativePath string, contents string) string {
	t.Helper()
	modulePath := filepath.Join(baseDir, relativePath)
	require.NoError(t, os.MkdirAll(filepath.Dir(modulePath), 0o755))
	require.NoError(t, os.WriteFile(modulePath, []byte(contents), 0o600))
	return modulePath
}

func templateDirAlias(t *testing.T, templateDir string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return templateDir, templateDir
	}
	aliasPath := filepath.Join(t.TempDir(), "templates-link")
	if err := os.Symlink(templateDir, aliasPath); err != nil {
		return templateDir, templateDir
	}
	return aliasPath, templateDir
}

func useRuntimePool(t *testing.T, runtime *goja.Runtime) {
	t.Helper()

	previousPool := gojapool
	pool := &sync.Pool{
		New: func() interface{} {
			return runtime
		},
	}
	pool.Put(runtime)
	gojapool = pool
	t.Cleanup(func() {
		gojapool = previousPool
	})
}

type noopWriter struct {
	Callback func(data []byte, level levels.Level)
}

func (n *noopWriter) Write(data []byte, level levels.Level) {
	if n.Callback != nil {
		n.Callback(data, level)
	}
}
