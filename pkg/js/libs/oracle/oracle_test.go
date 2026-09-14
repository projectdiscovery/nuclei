package oracle

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	go_ora "github.com/sijms/go-ora/v2"
	"github.com/stretchr/testify/require"
)

func TestSandboxDSNRejectsTraceFileOutsideTemplatesWithoutLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})

	traceFile := filepath.Join(t.TempDir(), "trace.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	_, err := sandboxDSN(executionID, dsn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-lfa is not enabled")
}

func TestConnectWithDSNRejectsTraceFileBeforeOracleOpen(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})

	traceFile := filepath.Join(t.TempDir(), "trace.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	ctx := context.WithValue(context.Background(), "executionId", executionID) // nolint:staticcheck
	_, err := (&OracleClient{}).ConnectWithDSN(ctx, dsn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-lfa is not enabled")
	require.NoFileExists(t, traceFile)
}

func TestSandboxDSNNormalizesTraceOptionsWithinTemplatesWithoutLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})

	traceFile := filepath.Join(templatesDir, "trace.log")
	traceDir := filepath.Join(templatesDir, "trace-dir")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE":      traceFile,
		"TRACE DIRECTORY": traceDir,
	})

	got, err := sandboxDSN(executionID, dsn)
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(got)
	require.NoError(t, err)
	require.Equal(t, traceFile, cfg.TraceFilePath)
	require.Equal(t, traceDir, cfg.TraceDir)
}

func TestSandboxDSNAllowsTraceFileOutsideTemplatesWithLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: true})

	traceFile := filepath.Join(t.TempDir(), "trace.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	got, err := sandboxDSN(executionID, dsn)
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(got)
	require.NoError(t, err)
	require.Equal(t, traceFile, cfg.TraceFilePath)
}

func restoreOracleTemplatesDir(t *testing.T, templatesDir string) {
	t.Helper()

	oldTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})
}
