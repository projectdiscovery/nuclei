package installer

import (
	"fmt"
	"os"
	"testing"
)

// TestMain gives this package its own temp directory. The templates update lock
// lives in os.TempDir and is machine wide, while `go test ./...` runs packages
// in parallel: tests here that took the lock queued behind other packages
// downloading the real nuclei-templates repo under it, which cost several
// minutes in CI for a test that does 40ms of work.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nuclei-installer-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create temp dir: %v\n", err)
		os.Exit(1)
	}
	// os.TempDir reads TMPDIR on unix and TMP then TEMP on windows
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		_ = os.Setenv(key, dir)
	}

	code := m.Run()

	_ = os.RemoveAll(dir)
	os.Exit(code)
}
