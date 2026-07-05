package fs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestReadFileAllowsTemplatesPath(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	templatesDir := t.TempDir()
	secret := []byte("fs-module-secret")
	path := filepath.Join(templatesDir, "allowed.txt")
	require.NoError(t, os.WriteFile(path, secret, 0o600))

	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck

	got, err := ReadFile(ctx, path)
	require.NoError(t, err)
	require.Equal(t, secret, got)
}

func TestReadFileRejectsPathOutsideAllowlist(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	templatesDir := t.TempDir()
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	outside := filepath.Join(home, ".nuclei-fs-module-"+t.Name(), "secret.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(outside), 0o700))
	require.NoError(t, os.WriteFile(outside, []byte("x"), 0o600))
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(outside)) })

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck

	_, err = ReadFile(ctx, outside)
	require.Error(t, err)
}

func TestListDirRejectsOutsideAllowlist(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	templatesDir := t.TempDir()
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	executionID := t.Name()
	protocolstate.SetLfaAllowed(&types.Options{ExecutionId: executionID, AllowLocalFileAccess: false})
	ctx := context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck

	_, err := ListDir(ctx, "/etc", "file")
	require.Error(t, err)
}
