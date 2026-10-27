package protocolstate_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

func TestSanitizeMySQLDSNStripsAllowAllFilesWithLFA(t *testing.T) {
	got, err := protocolstate.SanitizeMySQLDSN(
		"root:secret@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true",
		&types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true},
	)
	require.NoError(t, err)

	cfg, err := mysql.ParseDSN(got)
	require.NoError(t, err)
	require.False(t, cfg.AllowAllFiles, "-lfa must never disable the allowlist")
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

// recordMySQLRegistry swaps the mysql driver file registry for a recorder.
func recordMySQLRegistry(t *testing.T) map[string]bool {
	t.Helper()
	registered := map[string]bool{}
	restore := protocolstate.SwapMySQLLocalFileRegistry(
		func(path string) { registered[path] = true },
		func(path string) { delete(registered, path) },
	)
	t.Cleanup(restore)
	return registered
}

const mysqlLocalFilesDSN = "root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true"

// sqlPath escapes backslashes the way a MySQL string literal needs them, so
// Windows paths survive the round trip.
func sqlPath(p string) string {
	return strings.ReplaceAll(p, `\`, `\\`)
}

func TestRegisterMySQLLocalInfilesAllowsOnlyAllowlistedFiles(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)
	registered := recordMySQLRegistry(t)
	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true}

	inside := filepath.Join(templatesDir, "data.csv")
	require.NoError(t, os.WriteFile(inside, []byte("1\n"), 0o600))
	release, err := protocolstate.RegisterMySQLLocalInfiles(opts, mysqlLocalFilesDSN, "LOAD DATA LOCAL INFILE '"+sqlPath(inside)+"' INTO TABLE t")
	require.NoError(t, err)
	require.Equal(t, map[string]bool{inside: true}, registered)
	release()
	require.Empty(t, registered, "release must deregister the file")

	outside := outsideHomePath(t, ".nuclei-mysql-infile-"+t.Name())
	_, err = protocolstate.RegisterMySQLLocalInfiles(opts, mysqlLocalFilesDSN, `load data low_priority local infile "`+sqlPath(outside)+`" into table t`)
	require.ErrorIs(t, err, protocolstate.ErrPathDenied)
	require.Empty(t, registered)

	_, err = protocolstate.RegisterMySQLLocalInfiles(opts, mysqlLocalFilesDSN, "LOAD DATA LOCAL INFILE 'relative.csv' INTO TABLE t")
	require.ErrorIs(t, err, protocolstate.ErrPathDenied)
	require.Empty(t, registered)
}

func TestRegisterMySQLLocalInfilesNeedsLFAAndDSNOptIn(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)
	registered := recordMySQLRegistry(t)
	inside := filepath.Join(templatesDir, "data.csv")
	query := "LOAD DATA LOCAL INFILE '" + sqlPath(inside) + "' INTO TABLE t"

	release, err := protocolstate.RegisterMySQLLocalInfiles(&types.Options{ExecutionId: t.Name()}, mysqlLocalFilesDSN, query)
	require.NoError(t, err)
	release()
	require.Empty(t, registered, "nothing may be registered without -lfa")

	release, err = protocolstate.RegisterMySQLLocalInfiles(&types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true}, "root:x@nucleitcp(127.0.0.1:3306)/", query)
	require.NoError(t, err)
	release()
	require.Empty(t, registered, "nothing may be registered when the DSN does not ask for local files")
}

func TestRegisterMySQLLocalInfilesRefcountsSharedFiles(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)
	registered := recordMySQLRegistry(t)
	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true}
	inside := filepath.Join(templatesDir, "it's.csv")
	query := `LOAD DATA LOCAL INFILE '` + sqlPath(filepath.Join(templatesDir, "it''s.csv")) + `' INTO TABLE t`

	first, err := protocolstate.RegisterMySQLLocalInfiles(opts, mysqlLocalFilesDSN, query)
	require.NoError(t, err)
	second, err := protocolstate.RegisterMySQLLocalInfiles(opts, mysqlLocalFilesDSN, query)
	require.NoError(t, err)
	require.True(t, registered[inside], "escaped quote must decode to the real file name")

	first()
	first()
	require.True(t, registered[inside], "a concurrent query still needs the file")
	second()
	require.Empty(t, registered)
}
