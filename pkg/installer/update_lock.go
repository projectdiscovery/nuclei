package installer

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// withTemplatesUpdateLock serializes template install/update of templatesDir
// across processes. Parallel `go test` packages each have their own sync.Once,
// so without a cross-process lock they race on a shared templates directory
// (ENOENT, partial trees, checksum mismatches).
func withTemplatesUpdateLock(templatesDir string, fn func() error) error {
	lockPath := templatesUpdateLockPath(templatesDir)
	deadline := time.Now().Add(10 * time.Minute)

	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			defer func() {
				_ = f.Close()
				_ = os.Remove(lockPath)
			}()
			return fn()
		}

		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > 15*time.Minute {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return errkit.Wrap(err, "timed out waiting for nuclei templates update lock")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// templatesUpdateLockPath derives one lock per templates directory, so updates
// of different directories do not wait on each other. The parent is resolved
// rather than the directory itself because a fresh install locks a directory
// that does not exist yet, and both sides must derive the same path.
func templatesUpdateLockPath(templatesDir string) string {
	dir, err := filepath.Abs(templatesDir)
	if err != nil {
		dir = filepath.Clean(templatesDir)
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(dir)); err == nil {
		dir = filepath.Join(parent, filepath.Base(dir))
	}
	sum := sha256.Sum256([]byte(dir))
	return filepath.Join(os.TempDir(), fmt.Sprintf("nuclei-templates-update-%x.lock", sum[:8]))
}
