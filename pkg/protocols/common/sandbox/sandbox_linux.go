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
// libraries, TLS trust store, devices). They are landlock-only and never
// added to the template filesystem allowlist.
var hostRuntimeRODirs = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run", "/opt",
}

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

func applyPlatform(roots []string, includeRuntime bool) error {
	var opts []landlock.PathOpt
	if includeRuntime {
		if dirs := existingDirs(hostRuntimeRODirs); len(dirs) > 0 {
			opts = append(opts, landlock.RODirs(dirs...))
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
		opts = append(opts, landlock.RWDirs(dirs...))
	}
	if len(opts) == 0 {
		return ErrNoAllowedRoots
	}
	if err := landlock.V9.BestEffort().RestrictPaths(opts...); err != nil {
		return fmt.Errorf("landlock restrict: %w", err)
	}
	return nil
}

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
