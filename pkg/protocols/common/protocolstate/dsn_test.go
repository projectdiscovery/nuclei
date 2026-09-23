package protocolstate_test

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	go_ora "github.com/sijms/go-ora/v2"
	"github.com/stretchr/testify/require"
)

func TestSanitizeMySQLDSNStripsAllowAllFilesWithoutLFA(t *testing.T) {
	got, err := protocolstate.SanitizeMySQLDSN(
		"root:secret@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true",
		&types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false},
	)
	require.NoError(t, err)

	cfg, err := mysql.ParseDSN(got)
	require.NoError(t, err)
	require.False(t, cfg.AllowAllFiles)
}

func TestSanitizeMySQLDSNKeepsAllowAllFilesWithLFA(t *testing.T) {
	got, err := protocolstate.SanitizeMySQLDSN(
		"root:secret@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true",
		&types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true},
	)
	require.NoError(t, err)

	cfg, err := mysql.ParseDSN(got)
	require.NoError(t, err)
	require.True(t, cfg.AllowAllFiles)
}

func TestSanitizeMySQLDSNRejectsInvalidDSN(t *testing.T) {
	_, err := protocolstate.SanitizeMySQLDSN("::not-a-dsn::", &types.Options{})
	require.Error(t, err)
}

func TestSanitizeOracleDSNRejectsTraceFileOutsideAllowlist(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": "/etc/nuclei-oracle-trace.log",
	})
	_, err := protocolstate.SanitizeOracleDSN(t.Name(), dsn, &types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: false,
	})
	require.Error(t, err)
}

func TestSanitizeOracleDSNNormalizesTraceFileInsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	traceFile := filepath.Join(templatesDir, "trace.log")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE FILE": traceFile,
	})
	got, err := protocolstate.SanitizeOracleDSN(t.Name(), dsn, &types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: false,
	})
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(got)
	require.NoError(t, err)
	require.Equal(t, traceFile, cfg.TraceFilePath)
}

func TestSanitizeOracleDSNNormalizesTraceDirectory(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	traceDir := filepath.Join(templatesDir, "traces")
	dsn := go_ora.BuildUrl("127.0.0.1", 1521, "XE", "user", "pass", map[string]string{
		"TRACE DIRECTORY": traceDir,
	})
	got, err := protocolstate.SanitizeOracleDSN(t.Name(), dsn, &types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: false,
	})
	require.NoError(t, err)

	cfg, err := go_ora.ParseConfig(got)
	require.NoError(t, err)
	require.Equal(t, traceDir, cfg.TraceDir)
}

func TestSanitizeMSSQLDatabaseNameEscapesInjection(t *testing.T) {
	malicious := "master;DROP TABLE users--"
	got := protocolstate.SanitizeMSSQLDatabaseName(malicious)
	require.NotEqual(t, malicious, got)
	require.Equal(t, url.QueryEscape(malicious), got)
}

func TestSanitizePostgresDatabaseNameEscapesInjection(t *testing.T) {
	malicious := "../../etc/passwd"
	got := protocolstate.SanitizePostgresDatabaseName(malicious)
	require.NotEqual(t, malicious, got)
	require.Equal(t, url.PathEscape(malicious), got)
}
