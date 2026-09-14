//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	landlock "github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// hostRuntimeRODirs are paths a running nuclei process needs to read (shared
// libraries, TLS trust store, kernel interfaces). They are landlock-only and
// never added to the template filesystem allowlist. Home, /root and /var stay
// out so credentials and user data remain denied.
var hostRuntimeRODirs = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/opt",
}

// hostRuntimeRWDirs need writes for ordinary operation: /dev/null and friends
// are written by almost any process, and /run carries runtime sockets.
var hostRuntimeRWDirs = []string{"/dev", "/run"}

var containerSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
}

// platformSupported probes the running kernel for Landlock support instead of
// assuming it is always present on Linux. Without this, Supported() reports
// true on kernels that cannot enforce Landlock (e.g. CONFIG_SECURITY_LANDLOCK
// disabled, or the LSM not enabled at boot), which combined with BestEffort()
// would let Apply() return nil while the sandbox is effectively off.
func platformSupported() bool {
	v, err := llsyscall.LandlockGetABIVersion()
	return err == nil && v > 0
}

func applyPlatform(roots, owned []string, includeRuntime bool) error {
	var opts []landlock.Rule
	if includeRuntime {
		if dirs := existingDirs(hostRuntimeRODirs); len(dirs) > 0 {
			opts = append(opts, landlock.RODirs(dirs...))
		}
		if dirs := existingDirs(hostRuntimeRWDirs); len(dirs) > 0 {
			opts = append(opts, landlock.RWDirs(dirs...))
		}
		for _, sock := range containerSockets {
			if fileExists(sock) {
				opts = append(opts, landlock.RWFiles(sock))
			}
		}
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			if sock := filepath.Join(runtimeDir, "podman", "podman.sock"); fileExists(sock) {
				opts = append(opts, landlock.RWFiles(sock))
			}
		}
	}

	if dirs := existingDirs(roots); len(dirs) > 0 {
		opts = append(opts, writableDirs(dirs))
	}
	if dirs := ensureDirs(owned); len(dirs) > 0 {
		opts = append(opts, writableDirs(dirs))
	}
	if len(opts) == 0 {
		return ErrNoAllowedRoots
	}
	if err := landlock.V9.BestEffort().RestrictPaths(opts...); err != nil {
		return fmt.Errorf("landlock restrict: %w", err)
	}
	return nil
}

// writableDirs grants read-write access, adding the "refer" right when the
// kernel supports it. RWDirs alone forbids moving a file between two
// directories, which the kernel reports as EXDEV and which breaks ordinary
// work like unpacking a browser or swapping a template tree into place.
//
// Refer needs Landlock v2. Requesting it on a v1 kernel makes go-landlock
// downgrade the whole ruleset to a no-op, so on v1 we keep the plain rule and
// accept that cross-directory renames stay blocked rather than silently
// dropping the sandbox.
func writableDirs(dirs []string) landlock.Rule {
	rule := landlock.RWDirs(dirs...)
	if v, err := llsyscall.LandlockGetABIVersion(); err == nil && v >= 2 {
		return rule.WithRefer()
	}
	return rule
}

// ensureDirs is existingDirs for roots nuclei owns (templates, config, output).
// Landlock can only reference paths that already exist, and these are routinely
// absent on a first run, so a missing one is created rather than dropped:
// dropping it would leave the process unable to create it afterwards.
func ensureDirs(paths []string) []string {
	usable := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if mkErr := os.MkdirAll(path, 0o755); mkErr != nil {
				continue
			}
		}
		usable = append(usable, path)
	}
	return existingDirs(usable)
}

// existingDirs keeps only paths that are directories today, without creating
// anything. Used for host runtime paths, which must never be fabricated.
func existingDirs(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
