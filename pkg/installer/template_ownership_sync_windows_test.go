package installer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncTemplateOwnershipDirectory(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.NoError(t, syncTemplateOwnershipDirectory(root, "."))
}

func TestSyncTemplateOwnershipFileRestoresModeAfterOpenFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.NoError(t, root.WriteFile("restored.yaml", []byte("restored"), 0o444))
	originalInfo, err := root.Stat("restored.yaml")
	require.NoError(t, err)
	openErr := errors.New("open failed")

	err = syncTemplateOwnershipFileWithOpen(root, "restored.yaml", originalInfo.Mode(), func() (*os.File, error) {
		return nil, openErr
	})
	require.ErrorIs(t, err, openErr)
	info, err := root.Stat("restored.yaml")
	require.NoError(t, err)
	require.Equal(t, originalInfo.Mode().Perm(), info.Mode().Perm())
}

func TestRenameTemplateRestoreNoReplaceUsesOpenedRoot(t *testing.T) {
	parent := t.TempDir()
	openedParent := filepath.Join(parent, "opened")
	currentParent := filepath.Join(parent, "current")
	rootPath := filepath.Join(openedParent, "templates")
	currentRootPath := filepath.Join(currentParent, "templates")
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "source"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(rootPath, "destination"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(currentRootPath, "source"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(currentRootPath, "destination"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(currentRootPath, "source", "temporary.yaml"), []byte("wrong root"), 0o600))

	t.Chdir(openedParent)
	root, err := os.OpenRoot("templates")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.NoError(t, root.WriteFile(filepath.Join("source", "temporary.yaml"), []byte("restored"), 0o600))

	t.Chdir(currentParent)
	require.NoError(t, renameTemplateRestoreNoReplace(root, filepath.Join("source", "temporary.yaml"), filepath.Join("destination", "retired.yaml")))
	require.FileExists(t, filepath.Join(rootPath, "destination", "retired.yaml"))
	require.NoFileExists(t, filepath.Join(currentRootPath, "destination", "retired.yaml"))

	require.NoError(t, os.Rename(filepath.Join(rootPath, "source"), filepath.Join(rootPath, "moved-source")))
	require.NoError(t, os.Rename(filepath.Join(rootPath, "destination"), filepath.Join(rootPath, "moved-destination")))
}

func TestSyncTemplateOwnershipFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.NoError(t, root.WriteFile("restored.yaml", []byte("restored"), 0o444))
	require.NoError(t, syncTemplateOwnershipFile(root, "restored.yaml", 0o444))
	info, err := root.Stat("restored.yaml")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o444), info.Mode().Perm())
}
