//go:build linux

package sandbox

import (
	"fmt"

	landlock "github.com/landlock-lsm/go-landlock/landlock"
)

func platformSupported() bool {
	return true
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
