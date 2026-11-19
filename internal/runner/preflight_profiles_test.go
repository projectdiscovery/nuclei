package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
	"github.com/stretchr/testify/require"
)

type profiledInput struct {
	provider.InputProvider
	profiles *targetprofile.Registry
}

func (p profiledInput) TargetProfiles() *targetprofile.Registry { return p.profiles }

func TestFilteringInputProviderKeepsTargetProfiles(t *testing.T) {
	profiles := targetprofile.NewRegistry(t.TempDir())
	wrapped := &filteringInputProvider{base: profiledInput{profiles: profiles}}

	got, ok := any(wrapped).(interface {
		TargetProfiles() *targetprofile.Registry
	})
	require.True(t, ok)
	require.Same(t, profiles, got.TargetProfiles())
	require.Nil(t, (&filteringInputProvider{base: profiledInput{}}).TargetProfiles())
}
