package installer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/errkit"
)

// Tunables for withTemplatesUpdateLock. Package vars (instead of constants) so
// tests can shrink the 10m/15m windows without waiting them out.
var (
	templatesUpdateLockTimeout      = 10 * time.Minute
	templatesUpdateLockStaleAfter   = 15 * time.Minute
	templatesUpdateLockPollInterval = 250 * time.Millisecond
)

// withTemplatesUpdateLock serializes template install/update of templatesDir
// across processes. Parallel `go test` packages each have their own sync.Once,
// so without a cross-process lock they race on a shared templates directory
// (ENOENT, partial trees, checksum mismatches).
func withTemplatesUpdateLock(templatesDir string, fn func() error) error {
	lockPath := templatesUpdateLockPath(templatesDir)
	deadline := time.Now().Add(templatesUpdateLockTimeout)

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

		// Anything other than "already exists" (e.g. /tmp not writable,
		// read-only filesystem) will never succeed by retrying: fail fast
		// instead of spinning until the deadline.
		if !errors.Is(err, os.ErrExist) {
			return errkit.Wrapf(err, "could not create nuclei templates update lock at %s", lockPath)
		}

		info, statErr := os.Stat(lockPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				// Lost a race with the holder releasing the lock; retry
				// immediately instead of sleeping through the window.
				continue
			}
			if time.Now().After(deadline) {
				return errkit.Wrapf(err, "timed out waiting for nuclei templates update lock at %s (could not stat lock: %v); remove it manually if it is stale, or rerun with -duc/-disable-update-check to skip the automatic template update", lockPath, statErr)
			}
			time.Sleep(templatesUpdateLockPollInterval)
			continue
		}

		if age := time.Since(info.ModTime()); age > templatesUpdateLockStaleAfter {
			if rmErr := os.Remove(lockPath); rmErr != nil {
				// The classic multi-user hang: the lock lives in the shared
				// os.TempDir(), which has the sticky bit, so a lock file
				// created by another user cannot be unlinked (EPERM) by this
				// process. Retrying is pointless; surface who owns it and
				// how to recover instead of looping until the deadline.
				return errkit.Wrapf(rmErr, "stale nuclei templates update lock at %s (%s) could not be removed; it may belong to another user and cannot be unlinked from the shared temp dir, remove it manually (e.g. sudo rm %s) or rerun with -duc/-disable-update-check to skip the automatic template update", lockPath, describeUpdateLock(info, lockPath), lockPath)
			}
			continue
		}
		if time.Now().After(deadline) {
			return errkit.Wrapf(err, "timed out waiting for nuclei templates update lock at %s (%s); another process may be updating templates, if no update is running remove the stale lock manually (e.g. sudo rm %s) or rerun with -duc/-disable-update-check to skip the automatic template update", lockPath, describeUpdateLock(info, lockPath), lockPath)
		}
		time.Sleep(templatesUpdateLockPollInterval)
	}
}

// describeUpdateLock renders age, ownership and recorded pid of an existing
// lock for error messages. Everything is best-effort: the file is usually
// 0600, so a lock owned by another user may be neither readable nor statable
// beyond what os.Stat already returned.
func describeUpdateLock(info os.FileInfo, lockPath string) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("age %s", time.Since(info.ModTime()).Round(time.Second)))
	parts = append(parts, fmt.Sprintf("mode %s", info.Mode()))
	if uid, gid, ok := updateLockOwner(info); ok {
		extra := fmt.Sprintf("uid=%d gid=%d", uid, gid)
		if current := os.Getuid(); current >= 0 && uid != uint64(current) {
			extra += " (another user)"
		}
		parts = append(parts, extra)
	}
	if pid, err := os.ReadFile(lockPath); err == nil {
		if trimmed := strings.TrimSpace(string(pid)); trimmed != "" {
			parts = append(parts, fmt.Sprintf("pid %s", trimmed))
		}
	} else if os.IsPermission(err) {
		parts = append(parts, "pid unreadable (permission denied, likely another user)")
	}
	return strings.Join(parts, ", ")
}

// updateLockOwner extracts uid/gid from os.Stat without importing syscall
// directly (syscall.Stat_t does not exist on windows). It uses reflection on
// info.Sys(): on unix this is *syscall.Stat_t with Uid/Gid fields, elsewhere
// the assertion fails and ok=false is reported.
func updateLockOwner(info os.FileInfo) (uid, gid uint64, ok bool) {
	sys := info.Sys()
	if sys == nil {
		return 0, 0, false
	}
	v := reflect.ValueOf(sys)
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, 0, false
	}
	uidField := v.FieldByName("Uid")
	gidField := v.FieldByName("Gid")
	if !uidField.IsValid() || !gidField.IsValid() {
		return 0, 0, false
	}
	toUint := func(rv reflect.Value) (uint64, bool) {
		switch rv.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return rv.Uint(), true
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if n := rv.Int(); n >= 0 {
				return uint64(n), true
			}
		}
		return 0, false
	}
	u, okU := toUint(uidField)
	g, okG := toUint(gidField)
	if !okU || !okG {
		return 0, 0, false
	}
	return u, g, true
}

// templatesUpdateLockPath derives one lock per templates directory, so updates
// of different directories do not wait on each other. Every alias of a
// directory maps to the same lock, including a symlink whose target does not
// exist yet.
func templatesUpdateLockPath(templatesDir string) string {
	sum := sha256.Sum256([]byte(config.CanonicalTemplatesPath(templatesDir)))
	return filepath.Join(os.TempDir(), fmt.Sprintf("nuclei-templates-update-%x.lock", sum[:8]))
}
