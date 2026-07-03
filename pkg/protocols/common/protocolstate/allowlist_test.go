package protocolstate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestAllowedFileRootsAlwaysIncludesTemplatesAndTemp(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	roots := protocolstate.AllowedFileRoots(&types.Options{ExecutionId: t.Name()})
	require.NotEmpty(t, roots)
	require.True(t, rootListContains(roots, templatesDir), "templates dir must be in allowlist: %v", roots)
	require.True(t, rootListContains(roots, os.TempDir()), "temp dir must be in allowlist: %v", roots)
}

func TestAllowedFileRootsWithLFAIncludesCWD(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	roots := protocolstate.AllowedFileRoots(&types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: true,
	})
	require.True(t, rootListContains(roots, cwd), "cwd must be in allowlist when -lfa is enabled")
}

func TestAllowedFileRootsWithAllowedPaths(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	extraDir := t.TempDir()
	roots := protocolstate.AllowedFileRoots(&types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: true,
		AllowedPaths:         goflags.StringSlice{extraDir},
	})
	require.True(t, rootListContains(roots, extraDir))
}

func TestNormalizePathRejectsTraversalOutsideTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	_, err := protocolstate.NormalizePath(opts, "/etc/passwd")
	require.Error(t, err)
}

func TestNormalizePathAllowsFileInsideTemplatesViaRelativePath(t *testing.T) {
	templatesDir := t.TempDir()
	payload := filepath.Join(templatesDir, "helpers", "payload.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(payload), 0o700))
	require.NoError(t, os.WriteFile(payload, []byte("secret"), 0o600))
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	got, err := protocolstate.NormalizePath(opts, "helpers/payload.txt")
	require.NoError(t, err)
	require.Contains(t, got, "payload.txt")
}

func TestNormalizePathLFADoesNotBypassAbsoluteOutsideRoots(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: true,
	}
	_, err := protocolstate.NormalizePath(opts, "/etc/passwd")
	require.Error(t, err)
}

func TestNormalizePathAllowedPathsGrantAccessWithLFA(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	grantedDir := t.TempDir()
	secretPath := filepath.Join(grantedDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("x"), 0o600))

	opts := &types.Options{
		ExecutionId:          t.Name(),
		AllowLocalFileAccess: true,
		AllowedPaths:         goflags.StringSlice{grantedDir},
	}
	got, err := protocolstate.NormalizePath(opts, secretPath)
	require.NoError(t, err)
	require.Equal(t, secretPath, got)
}

func rootListContains(roots []string, target string) bool {
	cleanTarget, err := filepath.EvalSymlinks(filepath.Clean(target))
	if err != nil {
		cleanTarget = filepath.Clean(target)
	}
	for _, root := range roots {
		cleanRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			cleanRoot = filepath.Clean(root)
		}
		if cleanRoot == cleanTarget {
			return true
		}
	}
	return false
}
