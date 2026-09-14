//go:build !windows

package installer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteTemplateOutputHonorsUmask(t *testing.T) {
	previousUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	outputPath := filepath.Join(t.TempDir(), "official.yaml")
	_, err := writeTemplateOutput(filepath.Dir(outputPath), outputPath, []byte("release"), 0o666)
	require.NoError(t, err)
	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCopyQuarantinedTemplatePreservesMode(t *testing.T) {
	templatesDir := t.TempDir()
	quarantinePath := templateOwnershipRetiredPrefix + "mode"
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, quarantinePath), []byte("modified"), 0o644))

	previousUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	require.NoError(t, copyQuarantinedTemplate(root, "retired.yaml", quarantinePath))
	info, err := root.Stat("retired.yaml")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}
