package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplatesUpdateLockPath(t *testing.T) {
	t.Run("same directory, same lock", func(t *testing.T) {
		dir := t.TempDir()
		require.Equal(t, templatesUpdateLockPath(dir), templatesUpdateLockPath(dir+string(filepath.Separator)))
	})

	t.Run("different directories, different locks", func(t *testing.T) {
		require.NotEqual(t, templatesUpdateLockPath(t.TempDir()), templatesUpdateLockPath(t.TempDir()))
	})

	t.Run("stable across a fresh install creating the directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nuclei-templates")
		before := templatesUpdateLockPath(dir)
		require.NoError(t, os.Mkdir(dir, 0o755))
		require.Equal(t, before, templatesUpdateLockPath(dir))
	})
}
