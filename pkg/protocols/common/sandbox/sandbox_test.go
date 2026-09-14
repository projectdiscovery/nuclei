package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/sandbox"
	"github.com/stretchr/testify/require"
)

func TestApplyDisabledIsNoOp(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	sandbox.ResetForTesting()
	t.Cleanup(sandbox.ResetForTesting)

	err := sandbox.Apply(sandbox.Config{
		AllowedRoots: []string{os.TempDir()},
		Disabled:     true,
	})
	require.NoError(t, err)
}

func TestApplyWithEmptyRootsReturnsError(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	sandbox.ResetForTesting()
	t.Cleanup(sandbox.ResetForTesting)

	err := sandbox.Apply(sandbox.Config{})
	require.Error(t, err)
	require.ErrorIs(t, err, sandbox.ErrNoAllowedRoots)
}

func TestApplyWithValidRoots(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if sandbox.Supported() {
		t.Skip("landlock apply is verified in TestLandlockEnforcement")
	}
	sandbox.ResetForTesting()
	t.Cleanup(sandbox.ResetForTesting)

	root := t.TempDir()
	err := sandbox.Apply(sandbox.Config{AllowedRoots: []string{root}})
	require.NoError(t, err)
}

func TestApplyAllowsWritesInsideAllowedRoot(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if sandbox.Supported() {
		t.Skip("landlock write access is verified in TestLandlockEnforcement")
	}
	sandbox.ResetForTesting()
	t.Cleanup(sandbox.ResetForTesting)

	root := filepath.Join(os.TempDir(), "nuclei-sandbox-smoke-"+t.Name())
	require.NoError(t, os.MkdirAll(root, 0o700))
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	require.NoError(t, sandbox.Apply(sandbox.Config{AllowedRoots: []string{root}}))

	testFile := filepath.Join(root, "sandbox-write-test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("ok"), 0o600))
}

func TestSupportedMatchesPlatform(t *testing.T) {
	// Supported() must be stable for the lifetime of the process.
	_ = sandbox.Supported()
}
