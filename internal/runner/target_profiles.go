package runner

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// targetProfiles returns the per-target profiles read from input, or nil when
// no target has one.
func (r *Runner) targetProfiles() *targetprofile.Registry {
	provider, ok := r.inputProvider.(interface {
		TargetProfiles() *targetprofile.Registry
	})
	if !ok || !provider.TargetProfiles().Scoped() {
		return nil
	}
	return provider.TargetProfiles()
}

// hasPinnedTargets reports whether a target line pinned a target to an ip.
func (r *Runner) hasPinnedTargets() bool {
	provider, ok := r.inputProvider.(interface {
		PinnedTargets() bool
	})
	return ok && provider.PinnedTargets()
}

// pinnedTargetConflict returns an error for an option that cannot run with
// targets pinned to an ip.
func pinnedTargetConflict(options *types.Options) error {
	switch {
	case options.AutomaticScan:
		return errors.New("targets pinned to an ip cannot be combined with automatic scan")
	case options.AliveHttpProxy != "" || options.AliveSocksProxy != "":
		return errors.New("targets pinned to an ip cannot be combined with a proxy, as the proxy resolves the host itself")
	case options.ReplayProxy != "":
		return errors.New("targets pinned to an ip cannot be combined with -replay-proxy, as the replay proxy resolves the host itself")
	}
	return nil
}
