package mysql

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSandboxDSN(t *testing.T) {
	t.Run("strips allowAllFiles when lfa disabled", func(t *testing.T) {
		got, err := protocolstate.SanitizeMySQLDSN("root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true", &types.Options{})
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("keeps allowAllFiles when lfa enabled", func(t *testing.T) {
		got, err := protocolstate.SanitizeMySQLDSN("root:x@nucleitcp(127.0.0.1:3306)/?allowAllFiles=true", &types.Options{AllowLocalFileAccess: true})
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.True(t, cfg.AllowAllFiles)
	})

	t.Run("leaves dsn without allowAllFiles untouched", func(t *testing.T) {
		got, err := protocolstate.SanitizeMySQLDSN("root:x@nucleitcp(127.0.0.1:3306)/", &types.Options{})
		require.NoError(t, err)

		cfg, err := mysql.ParseDSN(got)
		require.NoError(t, err)
		require.False(t, cfg.AllowAllFiles)
	})

	t.Run("errors on invalid dsn", func(t *testing.T) {
		_, err := protocolstate.SanitizeMySQLDSN("::not-a-dsn::", &types.Options{})
		require.Error(t, err)
	})
}
