package protocols

import (
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/stretchr/testify/require"
)

func TestInteractshEvictionDuration(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Duration(0), (*ExecutorOptions)(nil).InteractshEvictionDuration())
	require.Equal(t, time.Duration(0), (&ExecutorOptions{}).InteractshEvictionDuration())
	require.Equal(t, 300*time.Second, (&ExecutorOptions{InteractshEviction: 300}).InteractshEvictionDuration())
}

func TestRegisterInteractshRequestSetsTemplateEviction(t *testing.T) {
	t.Parallel()

	client, err := interactsh.New(interactsh.DefaultOptions(nil, nil, nil))
	require.NoError(t, err)

	data := &interactsh.RequestData{}
	(&ExecutorOptions{Interactsh: client, InteractshEviction: 300}).RegisterInteractshRequest(nil, data)
	require.Equal(t, 300*time.Second, data.Eviction)

	data = &interactsh.RequestData{}
	(&ExecutorOptions{Interactsh: client}).RegisterInteractshRequest(nil, data)
	require.Equal(t, time.Duration(0), data.Eviction)
}
