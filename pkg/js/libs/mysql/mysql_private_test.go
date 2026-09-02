package mysql

import (
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBuildDSNMapsOptions(t *testing.T) {
	dsn, err := BuildDSN(MySQLOptions{
		Host: "127.0.0.1", Port: 3306, Username: "user", Password: "password",
		DbName: "app", Timeout: 7, RawQuery: "?tls=skip-verify",
	})
	require.NoError(t, err)

	cfg, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	require.Equal(t, "nucleitcp", cfg.Net)
	require.Equal(t, "127.0.0.1:3306", cfg.Addr)
	require.Equal(t, "app", cfg.DBName)
	require.Equal(t, 7*time.Second, cfg.Timeout)
	require.Equal(t, "skip-verify", cfg.TLSConfig)
}

func TestBuildDSNRejectsMissingHostOrPort(t *testing.T) {
	_, err := BuildDSN(MySQLOptions{Port: 3306})
	require.EqualError(t, err, "invalid host or port")
	_, err = BuildDSN(MySQLOptions{Host: "127.0.0.1"})
	require.EqualError(t, err, "invalid host or port")
}

func TestBuildDSNRejectsNonTCPProtocol(t *testing.T) {
	_, err := BuildDSN(MySQLOptions{Host: "127.0.0.1", Port: 3306, Protocol: "unix"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported mysql protocol")
}

func TestSandboxDSNForcesNucleiTCP(t *testing.T) {
	got, err := sandboxDSN("root:x@tcp(127.0.0.1:3306)/", false)
	require.NoError(t, err)

	cfg, err := mysql.ParseDSN(got)
	require.NoError(t, err)
	require.Equal(t, "nucleitcp", cfg.Net)
}

func TestSandboxDSNRejectsUnixSocket(t *testing.T) {
	_, err := sandboxDSN("root:x@unix(/var/run/mysqld.sock)/", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported mysql protocol")
}

func TestOpenDBDeniesRestrictedLocalHost(t *testing.T) {
	executionID := "mysql-open-deny-" + t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	_, err := openDB(executionID, "root:x@tcp(127.0.0.1:3306)/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "network policy")
	require.Contains(t, err.Error(), "127.0.0.1")
}

func TestSandboxDSN(t *testing.T) {
	t.Run("strips allowAllFiles when lfa disabled", func(t *testing.T) {
		got, err := sandboxDSN("root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true", false)
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("keeps allowAllFiles when lfa enabled", func(t *testing.T) {
		got, err := sandboxDSN("root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true", true)
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.True(t, cfg.AllowAllFiles)
	})

	t.Run("leaves dsn without allowAllFiles untouched", func(t *testing.T) {
		got, err := sandboxDSN("root:x@nucleitcp(127.0.0.1:3306)/", false)
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("errors on invalid dsn", func(t *testing.T) {
		_, err := sandboxDSN("::not-a-dsn::", false)
		require.Error(t, err)
	})
}
