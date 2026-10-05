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
		dir := filepath.Join(t.TempDir(), "missing", "nuclei-templates")
		before := templatesUpdateLockPath(dir)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.Equal(t, before, templatesUpdateLockPath(dir))
	})

	t.Run("symlink to a directory, same lock", func(t *testing.T) {
		dir := t.TempDir()
		link := filepath.Join(t.TempDir(), "templates-link")
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		require.Equal(t, templatesUpdateLockPath(dir), templatesUpdateLockPath(link))
	})
}
