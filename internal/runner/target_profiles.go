package runner

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
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
