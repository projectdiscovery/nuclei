package compiler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	_, err = compiler.ExecuteWithOptions(p, NewExecuteArgs(), &ExecuteOptions{Context: context.Background(),
		TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: time.Duration(20) * time.Second}},
	)
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
	firstValue, err := executeWithRuntime(runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: allowExecutionID,
		Context:     context.Background(),
	})
	require.NoError(t, err)
	require.Equal(t, "outside-ok", firstValue.Export())

	_, err = executeWithRuntime(runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: denyExecutionID,
		Context:     context.Background(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "-lfa is not enabled")
}

func executeScript(t *testing.T, executionID string, allowLocalFileAccess bool, script string) (ExecuteResult, error) {
	t.Helper()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: allowLocalFileAccess})

	compiled, err := SourceAutoMode(script, false)
	require.NoError(t, err)

	compiler := New()
	return compiler.ExecuteWithOptions(compiled, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: executionID,
		Context:     context.Background(),
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
