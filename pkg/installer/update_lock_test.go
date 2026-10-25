package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// errkit quotes the error chain, so a Windows path's backslashes are escaped
// in Error() even though the message itself contains the real path.
func requireErrorContainsPath(t *testing.T, err error, path string) {
	t.Helper()
	rendered := err.Error()
	if strings.Contains(rendered, path) || strings.Contains(rendered, strings.ReplaceAll(path, `\`, `\\`)) {
		return
	}
	require.Contains(t, rendered, path)
}

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

	t.Run("dangling symlink, same lock before and after creation", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "nuclei-templates")
		link := filepath.Join(parent, "templates-link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		require.Equal(t, templatesUpdateLockPath(target), templatesUpdateLockPath(link))
		require.Equal(t, templatesUpdateLockPath(filepath.Join(target, "nested")), templatesUpdateLockPath(filepath.Join(link, "nested")))

		require.NoError(t, os.MkdirAll(target, 0o755))
		require.Equal(t, templatesUpdateLockPath(target), templatesUpdateLockPath(link))
	})

	t.Run("relative dangling symlink, same lock", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "nuclei-templates")
		link := filepath.Join(parent, "templates-link")
		if err := os.Symlink("nuclei-templates", link); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		require.Equal(t, templatesUpdateLockPath(target), templatesUpdateLockPath(link))
	})
}

func TestWithTemplatesUpdateLockStaleLockIsCleared(t *testing.T) {
	dir := t.TempDir()
	lockPath := templatesUpdateLockPath(dir)
	require.NoError(t, os.WriteFile(lockPath, []byte("1234\n"), 0o600))
	stale := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(lockPath, stale, stale))
	t.Cleanup(func() { _ = os.Remove(lockPath) })

	ran := false
	require.NoError(t, withTemplatesUpdateLock(dir, func() error {
		ran = true
		return nil
	}))
	require.True(t, ran, "fn should run after the stale lock is cleared")
}

func TestWithTemplatesUpdateLockFreshLockTimesOutWithHelpfulMessage(t *testing.T) {
	oldTimeout, oldStale, oldPoll := templatesUpdateLockTimeout, templatesUpdateLockStaleAfter, templatesUpdateLockPollInterval
	templatesUpdateLockTimeout = 200 * time.Millisecond
	templatesUpdateLockStaleAfter = time.Hour
	templatesUpdateLockPollInterval = 10 * time.Millisecond
	defer func() {
		templatesUpdateLockTimeout, templatesUpdateLockStaleAfter, templatesUpdateLockPollInterval = oldTimeout, oldStale, oldPoll
	}()

	dir := t.TempDir()
	lockPath := templatesUpdateLockPath(dir)
	require.NoError(t, os.WriteFile(lockPath, []byte("99999\n"), 0o600))
	t.Cleanup(func() { _ = os.Remove(lockPath) })

	start := time.Now()
	err := withTemplatesUpdateLock(dir, func() error { return nil })
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Less(t, elapsed, 10*time.Second, "must fail fast instead of hanging")
	require.Contains(t, err.Error(), "timed out waiting for nuclei templates update lock")
	requireErrorContainsPath(t, err, lockPath)
	require.Contains(t, err.Error(), "-duc")
}

func TestWithTemplatesUpdateLockStaleLockAlreadyRemoved(t *testing.T) {
	previous := removeTemplatesUpdateLock
	t.Cleanup(func() { removeTemplatesUpdateLock = previous })
	removeTemplatesUpdateLock = func(path string) error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		// Another process removed the stale lock after we stat-ed it.
		return os.ErrNotExist
	}

	dir := t.TempDir()
	lockPath := templatesUpdateLockPath(dir)
	require.NoError(t, os.WriteFile(lockPath, []byte("1234\n"), 0o600))
	stale := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(lockPath, stale, stale))
	t.Cleanup(func() { _ = os.Remove(lockPath) })

	ran := false
	require.NoError(t, withTemplatesUpdateLock(dir, func() error {
		ran = true
		return nil
	}))
	require.True(t, ran, "a lock another process already removed must be taken, not treated as a failure")
}

func TestWithTemplatesUpdateLockUnremovableStaleLockFailsFast(t *testing.T) {
	previous := removeTemplatesUpdateLock
	t.Cleanup(func() { removeTemplatesUpdateLock = previous })
	removeTemplatesUpdateLock = func(string) error { return os.ErrPermission }

	dir := t.TempDir()
	lockPath := templatesUpdateLockPath(dir)
	require.NoError(t, os.WriteFile(lockPath, []byte("1234\n"), 0o600))
	stale := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(lockPath, stale, stale))
	t.Cleanup(func() { _ = os.Remove(lockPath) })

	ran := false
	start := time.Now()
	err := withTemplatesUpdateLock(dir, func() error {
		ran = true
		return nil
	})
	require.Error(t, err)
	require.False(t, ran)
	require.Less(t, time.Since(start), 2*time.Second)
	require.ErrorIs(t, err, os.ErrPermission)
	require.Contains(t, err.Error(), "could not be removed")
	requireErrorContainsPath(t, err, lockPath)
}
