//go:build linux

package installer

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyQuarantinedTemplateWithoutHardLinks(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	quarantinePath := templateOwnershipRetiredPrefix + "no-hard-links"
	contents := []byte("locally modified contents")
	require.NoError(t, root.WriteFile(quarantinePath, contents, 0o640))
	openQuarantine, err := root.OpenFile(quarantinePath, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, openQuarantine.Close()) })

	err = restoreQuarantinedTemplateWithLink(root, "retired.yaml", quarantinePath, func(string, string) error {
		return errors.ErrUnsupported
	})
	require.NoError(t, err)
	require.NoError(t, openQuarantine.Truncate(0))
	_, err = openQuarantine.WriteAt([]byte("late local write"), 0)
	require.NoError(t, err)
	restored, err := root.ReadFile("retired.yaml")
	require.NoError(t, err)
	require.Equal(t, []byte("late local write"), restored)
	info, err := root.Stat("retired.yaml")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestResumeTemplateRestoreStateWithoutHardLinks(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	retiredPath := "retired.yaml"
	quarantinePath := templateOwnershipRetiredPrefix + "pre-publication"
	contents := []byte("locally modified contents")
	require.NoError(t, root.WriteFile(quarantinePath, contents, 0o600))
	state, err := newTemplateRestoreState(retiredPath)
	require.NoError(t, err)
	state.kind = templateRestoreCopy
	state.digest = templateDigest(contents)
	require.NoError(t, root.WriteFile(state.temporaryPath, contents, 0o600))
	require.NoError(t, createTemplateRestoreState(root, state))

	completed, err := resumeTemplateRestoreState(root, state, quarantinePath, func(string, string) error {
		return errors.ErrUnsupported
	})
	require.NoError(t, err)
	require.False(t, completed)
	require.NoError(t, restoreQuarantinedTemplate(root, retiredPath, quarantinePath))
	restored, err := root.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, contents, restored)
	_, err = root.Lstat(state.statePath)
	require.ErrorIs(t, err, os.ErrNotExist)
}
