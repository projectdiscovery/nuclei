package protocolstate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestAllowedFileRootsAlwaysIncludesTemplatesAndScanTemp(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)
	scanTemp := t.TempDir()
	protocolstate.SetTemporaryDirectory(t.Name(), scanTemp)
	t.Cleanup(func() { protocolstate.SetTemporaryDirectory(t.Name(), "") })

	roots := protocolstate.AllowedFileRoots(&types.Options{ExecutionId: t.Name()})
	require.NotEmpty(t, roots)
	require.True(t, rootListContains(roots, templatesDir), "templates dir must be in allowlist: %v", roots)
	require.True(t, rootListContains(roots, scanTemp), "per-scan temp dir must be in allowlist: %v", roots)
}

// The shared system temp dir (/tmp on Linux) holds other users' and other
// programs' files, so templates must not reach it. Only the per-scan dir is
// allowed, while the process sandbox still keeps the system temp dir usable.
func TestSystemTempDirIsNotTemplateReadable(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)
	scanTemp := t.TempDir()
	protocolstate.SetTemporaryDirectory(t.Name(), scanTemp)
	t.Cleanup(func() { protocolstate.SetTemporaryDirectory(t.Name(), "") })

	opts := &types.Options{ExecutionId: t.Name()}
	roots := protocolstate.AllowedFileRoots(opts)
	require.False(t, rootListContains(roots, os.TempDir()), "system temp dir must not be in allowlist: %v", roots)

	sibling, err := os.MkdirTemp("", "nuclei-shared-tmp-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })
	shared := filepath.Join(sibling, "other-user-file")
	require.NoError(t, os.WriteFile(shared, []byte("x"), 0o600))
	_, err = protocolstate.NormalizePath(opts, shared)
	require.ErrorIs(t, err, protocolstate.ErrPathDenied)

	inScan := filepath.Join(scanTemp, "scan-file")
	require.NoError(t, os.WriteFile(inScan, []byte("x"), 0o600))
	_, err = protocolstate.NormalizePath(opts, inScan)
	require.NoError(t, err)

	require.True(t, rootListContains(protocolstate.SandboxFileRoots(opts), os.TempDir()), "process sandbox must keep the system temp dir usable")

	protocolstate.SetTemporaryDirectory(t.Name(), "")
	require.False(t, rootListContains(protocolstate.AllowedFileRoots(opts), scanTemp), "cleared per-scan temp dir must leave the allowlist")
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

// The OS sandbox restricts the whole process, so it must keep nuclei's own
// CLI inputs and outputs reachable even though templates may not read them.
// Without this, `nuclei -l targets.txt` fails with permission denied.
func TestSandboxFileRootsCoversCLIPathsButAllowlistDoesNot(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	workDir := t.TempDir()
	targets := filepath.Join(workDir, "targets.txt")
	require.NoError(t, os.WriteFile(targets, []byte("scanme.sh\n"), 0o600))

	outputDir := t.TempDir()
	opts := &types.Options{
		ExecutionId:     t.Name(),
		TargetsFilePath: targets,
		Output:          filepath.Join(outputDir, "results.txt"),
	}

	sandboxRoots := protocolstate.SandboxFileRoots(opts)
	require.True(t, rootListContains(sandboxRoots, workDir), "targets file dir must be sandbox-reachable: %v", sandboxRoots)

	ownedRoots := protocolstate.SandboxOwnedFileRoots(opts)
	require.True(t, rootListContains(ownedRoots, outputDir), "output dir must be sandbox-reachable even before the file exists: %v", ownedRoots)

	// the template-facing allowlist stays narrow
	allowlist := protocolstate.AllowedFileRoots(opts)
	require.False(t, rootListContains(allowlist, workDir), "templates must not gain access to the targets dir: %v", allowlist)
}

// Template updates write templates.json under the state dir, so the sandbox
// must cover it while templates themselves stay locked out of it.
func TestSandboxFileRootsCoversStateAndCacheDirs(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{ExecutionId: t.Name()}
	roots := protocolstate.SandboxOwnedFileRoots(opts)
	allowlist := protocolstate.AllowedFileRoots(opts)

	for _, dir := range []string{config.DefaultConfig.GetConfigDir(), config.DefaultConfig.GetStateDir(), config.DefaultConfig.GetCacheDir()} {
		require.NotEmpty(t, dir)
		require.True(t, rootListContains(roots, dir), "sandbox must own %s: %v", dir, roots)
		require.False(t, rootListContains(allowlist, dir), "templates must not reach %s: %v", dir, allowlist)
	}
}

// The config dir holds the template signing private key, so a template must
// not read it even when nothing else denies the path.
func TestNormalizePathDeniesSigningKeysDir(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	keyPath := filepath.Join(config.DefaultConfig.GetKeysDir(), "nuclei-user-private-key.pem")
	_, err := protocolstate.NormalizePath(&types.Options{ExecutionId: t.Name()}, keyPath)
	require.ErrorIs(t, err, protocolstate.ErrPathDenied)
}

// A missing -t path must never be treated as an owned root. Creating it would
// leave an empty directory that template resolution then prefers over the real
// templates dir, which silently loads zero templates.
func TestSandboxOwnedRootsExcludeTemplateInputPaths(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	opts := &types.Options{
		ExecutionId: t.Name(),
		Templates:   goflags.StringSlice{"http/cves/"},
	}

	owned := protocolstate.SandboxOwnedFileRoots(opts)
	for _, root := range owned {
		require.NotContains(t, root, filepath.Join("http", "cves"), "template input path must not be an owned root: %v", owned)
	}
}

func TestSandboxOwnedRootsCoverBrowserProfileOnlyForHeadless(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	configDir, err := os.UserConfigDir()
	require.NoError(t, err)
	profile := filepath.Join(configDir, "chromium")

	// go-rod starts a cached browser without -user-data-dir to check it still
	// works, so chrome falls back here. Denying it makes go-rod re-download the
	// browser on every run.
	headless := protocolstate.SandboxOwnedFileRoots(&types.Options{ExecutionId: t.Name(), Headless: true})
	require.Contains(t, headless, profile, "headless runs must own the browser profile dir: %v", headless)

	plain := protocolstate.SandboxOwnedFileRoots(&types.Options{ExecutionId: t.Name()})
	require.NotContains(t, plain, profile, "non-headless runs must not create a browser profile dir: %v", plain)
}

func TestSandboxFileRootsIncludesWorkingDirectory(t *testing.T) {
	templatesDir := t.TempDir()
	restoreTemplatesDir(t, templatesDir)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	roots := protocolstate.SandboxFileRoots(&types.Options{ExecutionId: t.Name()})
	require.True(t, rootListContains(roots, cwd), "cwd must be sandbox-reachable without -lfa: %v", roots)
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
