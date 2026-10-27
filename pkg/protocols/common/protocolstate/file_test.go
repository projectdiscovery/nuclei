package protocolstate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// outsideAllowlistPath returns an absolute path outside the sandbox allowlist
// on every OS. "/etc/passwd" is not absolute on Windows and would resolve
// relative to the templates dir (failing with "does not exist" before the
// allowlist check); rooting at the temp volume keeps it drive-qualified yet
// outside the templates/temp/cwd roots.
func outsideAllowlistPath(name string) string {
	root := filepath.VolumeName(os.TempDir()) + string(os.PathSeparator)
	return filepath.Join(root, "nuclei-denied", name)
}

func TestNormalizePathRejectsOutsideAllowlistWithoutLFA(t *testing.T) {
	templatesDir := t.TempDir()
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	_, err := protocolstate.NormalizePath(opts, outsideAllowlistPath("passwd"))
	require.Error(t, err)
}

func TestNormalizePathAllowsTemplatesDir(t *testing.T) {
	templatesDir := t.TempDir()
	payloadPath := filepath.Join(templatesDir, "payload.txt")
	require.NoError(t, os.WriteFile(payloadPath, []byte("ok"), 0o600))
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	got, err := protocolstate.NormalizePath(opts, payloadPath)
	require.NoError(t, err)
	require.Contains(t, got, templatesDir)
}

func TestNormalizePathLFADoesNotBypassAllowlist(t *testing.T) {
	templatesDir := t.TempDir()
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: true}
	_, err := protocolstate.NormalizePath(opts, outsideAllowlistPath("passwd"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "allowed directories")
}

func TestIsHostAllowedFailsClosedWithoutDialers(t *testing.T) {
	require.False(t, protocolstate.IsHostAllowed("missing-execution-id", "127.0.0.1:80"))
}

func TestDialAllowedRequiresExecutionID(t *testing.T) {
	_, err := protocolstate.DialAllowed(context.Background(), "tcp", "127.0.0.1:80")
	require.Error(t, err)
}
