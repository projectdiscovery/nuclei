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

func TestBuildOracleDSNMapsOptions(t *testing.T) {
	dsn, err := buildOracleDSN(OracleOptions{
		Host: "127.0.0.1", Port: 1521, ServiceName: "XE", Username: "user", Password: "pass",
	})
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(dsn)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	require.Equal(t, "127.0.0.1", cfg.Servers[0].Addr)
	require.Equal(t, 1521, cfg.Servers[0].Port)
	require.Equal(t, "XE", cfg.ServiceName)
}

func TestBuildOracleDSNValidatesTarget(t *testing.T) {
	_, err := buildOracleDSN(OracleOptions{Port: 1521, ServiceName: "XE"})
	require.EqualError(t, err, "invalid host or port")
	_, err = buildOracleDSN(OracleOptions{Host: "127.0.0.1", Port: 1521})
	require.EqualError(t, err, "service name cannot be empty")
}

func TestConnectWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	ctx := context.WithValue(context.Background(), "executionId", executionID) // nolint:staticcheck
	connected, err := (&OracleClient{}).ConnectWithOptions(ctx, OracleOptions{
		Host: "127.0.0.1", Port: 1521, ServiceName: "XE", Username: "user", Password: "pass",
	})
	require.False(t, connected)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network policy")
	require.Contains(t, err.Error(), "127.0.0.1")
}
