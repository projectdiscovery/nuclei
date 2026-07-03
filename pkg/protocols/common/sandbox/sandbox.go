package sandbox

import (
	"sync"

	"github.com/projectdiscovery/gologger"
)

var (
	appliedOnce sync.Once
	appliedErr  error
)

// Config configures filesystem sandbox enforcement.
type Config struct {
	AllowedRoots []string
	Disabled     bool
}

// ResetForTesting clears the apply-once gate. It must only be used from tests.
func ResetForTesting() {
	appliedOnce = sync.Once{}
	appliedErr = nil
}

// Apply enforces the OS-level filesystem sandbox when supported.
// It is safe to call multiple times; only the first successful apply wins.
func Apply(cfg Config) error {
	if cfg.Disabled {
		return nil
	}
	appliedOnce.Do(func() {
		if len(cfg.AllowedRoots) == 0 {
			appliedErr = ErrNoAllowedRoots
			gologger.Warning().Msgf("filesystem sandbox skipped: %v", appliedErr)
			return
		}
		if !Supported() {
			gologger.Warning().Msg("filesystem sandbox is not supported on this platform; relying on Go-level path broker only")
			return
		}
		appliedErr = applyPlatform(cfg.AllowedRoots)
		if appliedErr != nil {
			gologger.Warning().Msgf("filesystem sandbox not applied: %v", appliedErr)
		}
	})
	return appliedErr
}

// Supported reports whether an OS-level filesystem sandbox is available.
func Supported() bool {
	return platformSupported()
}
