package oracle

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	go_ora "github.com/sijms/go-ora/v2"
	"github.com/stretchr/testify/require"
)

// outsideTemplatesPath returns an absolute path that is guaranteed to sit
// outside the sandbox allowlist on every OS. A Unix-style "/etc/..." literal is
// not absolute on Windows, so it would be resolved relative to the templates
// dir and fail with a "does not exist" error before the allowlist check ever
// runs. Rooting at the temp volume keeps it drive-qualified on Windows yet
// never inside the templates/temp/cwd roots.
func outsideTemplatesPath(name string) string {
	root := filepath.VolumeName(os.TempDir()) + string(os.PathSeparator)
	return filepath.Join(root, "nuclei-denied", name)
}

func TestSandboxDSNRejectsTraceFileOutsideTemplatesWithoutLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})

	traceFile := outsideTemplatesPath("nuclei-oracle-trace-test.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	_, err := protocolstate.SanitizeOracleDSN(executionID, dsn, &types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside")
}

func TestConnectWithDSNRejectsTraceFileBeforeOracleOpen(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})

	traceFile := outsideTemplatesPath("nuclei-oracle-connect-trace-test.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	ctx := context.WithValue(context.Background(), "executionId", executionID) // nolint:staticcheck
	_, err := (&OracleClient{}).ConnectWithDSN(ctx, dsn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside")
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

	got, err := protocolstate.SanitizeOracleDSN(executionID, dsn, &types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(got)
	require.NoError(t, err)
	require.Equal(t, traceFile, cfg.TraceFilePath)
	require.Equal(t, traceDir, cfg.TraceDir)
}

func TestSandboxDSNAllowsTraceFileWithinAllowedPathsWithLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreOracleTemplatesDir(t, templatesDir)

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: true})

	traceFile := filepath.Join(templatesDir, "trace.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})

	got, err := protocolstate.SanitizeOracleDSN(executionID, dsn, &types.Options{ExecutionId: executionID, AllowLocalFileAccess: true})
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
