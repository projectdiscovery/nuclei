package protocols

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExecutorOptionsCopyPreservesInteractshScope(t *testing.T) {
	client, err := interactsh.New(interactsh.DefaultOptions(nil, nil, nil))
	require.NoError(t, err)
	scope := client.NewRequestScope()

	copy := (&ExecutorOptions{Interactsh: client, InteractshScope: scope}).Copy()
	require.Same(t, client, copy.Interactsh)
	require.Same(t, scope, copy.InteractshScope)
}

func TestExecutorOptionsApplyNewEngineOptionsReplacesInteractshScope(t *testing.T) {
	client, err := interactsh.New(interactsh.DefaultOptions(nil, nil, nil))
	require.NoError(t, err)
	previous := client.NewRequestScope()
	next := client.NewRequestScope()

	reused := &ExecutorOptions{Interactsh: client, InteractshScope: previous}
	reused.ApplyNewEngineOptions(&ExecutorOptions{
		Options:         &types.Options{},
		Interactsh:      client,
		InteractshScope: next,
	})

	require.Same(t, next, reused.InteractshScope)
}
