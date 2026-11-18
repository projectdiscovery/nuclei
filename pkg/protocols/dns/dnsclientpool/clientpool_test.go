package dnsclientpool

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestClientsFollowResolverList(t *testing.T) {
	previousClient := normalClient
	previousPool := clientPool
	t.Cleanup(func() {
		normalClient = previousClient
		clientPool = previousPool
	})
	normalClient = nil
	clientPool = nil

	firstOptions := &types.Options{InternalResolversList: []string{"192.0.2.1:53"}}
	secondOptions := &types.Options{InternalResolversList: []string{"192.0.2.2:53"}}

	require.NoError(t, Init(firstOptions))
	require.NoError(t, Init(secondOptions))

	first, err := Get(firstOptions, &Configuration{})
	require.NoError(t, err)
	second, err := Get(secondOptions, &Configuration{})
	require.NoError(t, err)
	require.NotSame(t, first, second)

	again, err := Get(firstOptions, &Configuration{})
	require.NoError(t, err)
	require.Same(t, first, again)
}
