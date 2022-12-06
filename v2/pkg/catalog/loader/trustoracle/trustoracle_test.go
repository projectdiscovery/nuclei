package trustoracle

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestTrustOracle(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "")
	require.Nil(t, err)
	tmpfile.WriteString("code-template1\ncode-template2\n")
	err = tmpfile.Close()
	require.Nil(t, err)
	filename := tmpfile.Name()
	defer os.RemoveAll(filename)

	t.Run("empty oracle", func(t *testing.T) {
		o, err := NewOracle()
		require.Nil(t, err)
		require.Empty(t, o.db)
		require.Empty(t, o.seen)
	})
	t.Run("db-oracle", func(t *testing.T) {
		o, err := NewOracleWithDb(filename)
		require.Nil(t, err)
		require.Equal(t, filename, o.db)
		expected := []string{"code-template1", "code-template2"}
		require.ElementsMatch(t, expected, maps.Keys(o.seen))
	})
	t.Run("db-items", func(t *testing.T) {
		o, err := NewOracle()
		require.Nil(t, err)
		require.False(t, o.HasSeen("aa"))
		o.MarkSeen("aa")
		require.True(t, o.HasSeen("aa"))
	})
}
