package mysql

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

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
