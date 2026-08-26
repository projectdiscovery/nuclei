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

const landlockWorkerEnv = "NUCLEI_LANDLOCK_WORKER"

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

	require.NoError(t, sandbox.Apply(sandbox.Config{AllowedRoots: []string{root}}))

	inside, err := os.ReadFile(allowedFile)
	require.NoError(t, err)
	require.Equal(t, []byte("inside"), inside)

	_, err = os.ReadFile("/etc/passwd")
	require.Error(t, err, "landlock should deny reads outside allowed roots")
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
