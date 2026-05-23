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

	"github.com/Mzack9999/goja"
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

type noopWriter struct {
	Callback func(data []byte, level levels.Level)
}

func (n *noopWriter) Write(data []byte, level levels.Level) {
	if n.Callback != nil {
		n.Callback(data, level)
	}
}
