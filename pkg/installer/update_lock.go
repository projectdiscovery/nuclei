package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

const templatesUpdateLockName = "nuclei-templates-update.lock"

// withTemplatesUpdateLock serializes template install/update across processes.
// Parallel `go test` packages each have their own sync.Once, so without a
// cross-process lock they race on the shared templates directory (ENOENT,
// partial trees, checksum mismatches).
func withTemplatesUpdateLock(fn func() error) error {
	lockPath := filepath.Join(os.TempDir(), templatesUpdateLockName)
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
