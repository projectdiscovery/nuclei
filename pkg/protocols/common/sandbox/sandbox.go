package sandbox

import (
	"sync"

	"github.com/projectdiscovery/gologger"
)

var (
	applyMu sync.Mutex
	// applied is latched only once the sandbox reaches a terminal state:
	// successfully enforced, or provably unavailable on this platform. Failures
	// (missing roots, transient apply errors) do not latch, so a later call with
	// a valid Config can still succeed.
	applied bool
)

// Config configures filesystem sandbox enforcement.
type Config struct {
	AllowedRoots []string
	Disabled     bool
}

// ResetForTesting clears the apply-once gate. It must only be used from tests.
func ResetForTesting() {
	applyMu.Lock()
	defer applyMu.Unlock()
	applied = false
}

// Apply enforces the OS-level filesystem sandbox when supported.
// It is safe to call multiple times; only the first successful apply wins.
// A failed attempt does not latch, so a subsequent call with a valid Config can
// still enforce the sandbox.
func Apply(cfg Config) error {
	if cfg.Disabled {
		return nil
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	if applied {
		return nil
	}
	if len(cfg.AllowedRoots) == 0 {
		gologger.Warning().Msgf("filesystem sandbox skipped: %v", ErrNoAllowedRoots)
		return ErrNoAllowedRoots
	}
	if !Supported() {
		gologger.Warning().Msg("filesystem sandbox is not supported on this platform; relying on Go-level path broker only")
		applied = true
		return nil
	}
	if err := applyPlatform(cfg.AllowedRoots); err != nil {
		gologger.Warning().Msgf("filesystem sandbox not applied: %v", err)
		return err
	}
	applied = true
	return nil
}

// Supported reports whether an OS-level filesystem sandbox is available.
func Supported() bool {
	return platformSupported()
}
