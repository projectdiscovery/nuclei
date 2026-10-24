package mysql

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestSandboxDSN(t *testing.T) {
	t.Run("strips allowAllFiles when lfa disabled", func(t *testing.T) {
		got, err := sandboxDSN("", "root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true")
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("keeps allowAllFiles when lfa enabled", func(t *testing.T) {
		executionID := "mysql-lfa-" + t.Name()
		require.NoError(t, protocolstate.Init(&types.Options{
			ExecutionId:          executionID,
			AllowLocalFileAccess: true,
		}))
		t.Cleanup(func() { protocolstate.Close(executionID) })

		got, err := sandboxDSN(executionID, "root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true")
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.True(t, cfg.AllowAllFiles)
	})

	t.Run("leaves dsn without allowAllFiles untouched", func(t *testing.T) {
		got, err := sandboxDSN("", "root:x@nucleitcp(127.0.0.1:3306)/")
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("rewrites tcp to nucleitcp", func(t *testing.T) {
		got, err := sandboxDSN("", "root:x@tcp(acme.com:3306)/")
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.Equal(t, "nucleitcp", cfg.Net)
		require.Equal(t, "acme.com:3306", cfg.Addr)
	})

	t.Run("errors on invalid dsn", func(t *testing.T) {
		_, err := sandboxDSN("", "::not-a-dsn::")
		require.Error(t, err)
	})

	t.Run("denies loopback tcp when lna enabled", func(t *testing.T) {
		executionID := "mysql-lna-tcp-" + t.Name()
		require.NoError(t, protocolstate.Init(&types.Options{
			ExecutionId:                executionID,
			RestrictLocalNetworkAccess: true,
		}))
		t.Cleanup(func() { protocolstate.Close(executionID) })

		_, err := sandboxDSN(executionID, "vuser:vpass@tcp(127.0.0.1:3306)/vdb")
		require.Error(t, err)
		require.Contains(t, err.Error(), "127.0.0.1")
	})

	t.Run("denies unix socket when lna enabled", func(t *testing.T) {
		executionID := "mysql-lna-unix-" + t.Name()
		require.NoError(t, protocolstate.Init(&types.Options{
			ExecutionId:                executionID,
			RestrictLocalNetworkAccess: true,
		}))
		t.Cleanup(func() { protocolstate.Close(executionID) })

		_, err := sandboxDSN(executionID, "vuser:vpass@unix(/tmp/nuclei-mysql-lna.sock)/vdb")
		require.Error(t, err)
		require.Contains(t, err.Error(), "127.0.0.1")
	})
}
