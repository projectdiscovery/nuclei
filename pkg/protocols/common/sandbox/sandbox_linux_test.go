//go:build linux

package sandbox_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/sandbox"
	"github.com/stretchr/testify/require"
)

const (
	landlockWorkerEnv        = "NUCLEI_LANDLOCK_WORKER"
	landlockRuntimeWorkerEnv = "NUCLEI_LANDLOCK_RUNTIME_WORKER"
)

// TestLandlockEnforcement runs real Landlock checks in a child process because
// restrictions cannot be lifted once applied to the current process.
func TestLandlockEnforcement(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if !sandbox.Supported() {
		t.Skip("landlock is not supported on this kernel")
	}

	if os.Getenv(landlockWorkerEnv) == "1" {
		runLandlockWorker(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockEnforcement$", "-test.count=1")
	cmd.Env = append(os.Environ(), landlockWorkerEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("landlock worker failed: %v\n%s", err, string(out))
	}
}

func runLandlockWorker(t *testing.T) {
	t.Helper()
	sandbox.ResetForTesting()

	root, err := os.MkdirTemp("", "nuclei-landlock-*")
	require.NoError(t, err)

	allowedFile := filepath.Join(root, "allowed.txt")
	require.NoError(t, os.WriteFile(allowedFile, []byte("inside"), 0o600))

	missing := filepath.Join(root, "does-not-exist")
	require.NoError(t, sandbox.Apply(sandbox.Config{AllowedRoots: []string{root, missing}}))

	inside, err := os.ReadFile(allowedFile)
	require.NoError(t, err)
	require.Equal(t, []byte("inside"), inside)

	_, err = os.ReadFile("/etc/passwd")
	require.Error(t, err, "landlock should deny reads outside allowed roots")
	require.True(t, isPermissionError(err), "expected permission error, got: %v", err)

	// Landlock blocks cleanup of dirs under /tmp; exit before test teardown.
	os.Exit(0)
}

// TestLandlockRuntimePaths covers the production configuration, where the
// sandbox must stay usable for nuclei itself: reading a CLI-supplied file from
// the working directory and writing /dev/null both have to keep working, while
// unrelated user data stays denied.
func TestLandlockRuntimePaths(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if !sandbox.Supported() {
		t.Skip("landlock is not supported on this kernel")
	}

	if os.Getenv(landlockRuntimeWorkerEnv) == "1" {
		runLandlockRuntimeWorker(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockRuntimePaths$", "-test.count=1")
	cmd.Env = append(os.Environ(), landlockRuntimeWorkerEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("landlock runtime worker failed: %v\n%s", err, string(out))
	}
}

func runLandlockRuntimeWorker(t *testing.T) {
	t.Helper()
	sandbox.ResetForTesting()

	workDir, err := os.MkdirTemp("", "nuclei-landlock-cwd-*")
	require.NoError(t, err)

	targets := filepath.Join(workDir, "targets.txt")
	require.NoError(t, os.WriteFile(targets, []byte("scanme.sh\n"), 0o600))

	denied := filepath.Join(workDir, "..", "nuclei-landlock-denied")
	require.NoError(t, os.MkdirAll(denied, 0o700))
	secret := filepath.Join(denied, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))

	require.NoError(t, sandbox.Apply(sandbox.Config{
		AllowedRoots:   []string{workDir},
		IncludeRuntime: true,
	}))

	got, err := os.ReadFile(targets)
	require.NoError(t, err, "CLI target list must stay readable under the sandbox")
	require.Equal(t, []byte("scanme.sh\n"), got)

	require.NoError(t, os.WriteFile("/dev/null", []byte("x"), 0o600), "/dev/null must stay writable")

	_, err = os.ReadFile(secret)
	require.Error(t, err, "paths outside the granted roots must stay denied")
	require.True(t, isPermissionError(err), "expected permission error, got: %v", err)

	// Landlock blocks cleanup of dirs under /tmp; exit before test teardown.
	os.Exit(0)
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted")
}
