//go:build linux

package sandbox

import (
	"fmt"

	landlock "github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// platformSupported probes the running kernel for Landlock support instead of
// assuming it is always present on Linux. Without this, Supported() reports
// true on kernels that cannot enforce Landlock (e.g. CONFIG_SECURITY_LANDLOCK
// disabled, or the LSM not enabled at boot), which combined with BestEffort()
// would let Apply() return nil while the sandbox is effectively off.
func platformSupported() bool {
	v, err := llsyscall.LandlockGetABIVersion()
	return err == nil && v > 0
}

func applyPlatform(roots []string) error {
	if len(roots) == 0 {
		return ErrNoAllowedRoots
	}
	err := landlock.V9.BestEffort().RestrictPaths(
		landlock.RWDirs(roots...),
	)
	if err != nil {
		return fmt.Errorf("landlock restrict: %w", err)
	}
	return nil
}
