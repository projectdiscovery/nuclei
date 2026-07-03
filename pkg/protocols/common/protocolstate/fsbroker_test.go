package protocolstate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestReadFileAllowedReadsInsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	secret := []byte("template-secret")
	path := filepath.Join(templatesDir, "secret.txt")
	require.NoError(t, os.WriteFile(path, secret, 0o600))
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	got, err := protocolstate.ReadFileAllowed(opts, path)
	require.NoError(t, err)
	require.Equal(t, secret, got)
}

func TestReadFileAllowedRejectsOutsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	outside := filepath.Join(os.Getenv("HOME"), ".nuclei-fsbroker-outside-"+t.Name(), "secret.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(outside), 0o700))
	require.NoError(t, os.WriteFile(outside, []byte("x"), 0o600))
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(outside)) })

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	_, err := protocolstate.ReadFileAllowed(opts, outside)
	require.Error(t, err)
}

func TestWriteFileAllowedWritesInsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	target := filepath.Join(templatesDir, "written.txt")
	require.NoError(t, protocolstate.WriteFileAllowed(opts, target, []byte("data"), 0o600))

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("data"), got)
}

func TestWriteFileAllowedRejectsOutsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	outside := filepath.Join(os.Getenv("HOME"), ".nuclei-fsbroker-write-"+t.Name(), "out.txt")
	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	err := protocolstate.WriteFileAllowed(opts, outside, []byte("x"), 0o600)
	require.Error(t, err)
}
