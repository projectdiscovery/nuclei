package interactsh

import (
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestEvictionFromSeconds(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Duration(0), EvictionFromSeconds(0))
	require.Equal(t, time.Duration(0), EvictionFromSeconds(-1))
	require.Equal(t, 300*time.Second, EvictionFromSeconds(300))
}

func TestClientEvictionForUsesRequestOverride(t *testing.T) {
	t.Parallel()

	client, err := New(&Options{Eviction: 60 * time.Second, CacheSize: 10})
	require.NoError(t, err)

	require.Equal(t, 60*time.Second, client.evictionFor(nil))
	require.Equal(t, 60*time.Second, client.evictionFor(&RequestData{}))
	require.Equal(t, 300*time.Second, client.evictionFor(&RequestData{Eviction: 300 * time.Second}))
}

func TestRequestEventStoresWithPerRequestEviction(t *testing.T) {
	t.Parallel()

	client, err := New(&Options{Eviction: 60 * time.Second, CacheSize: 10})
	require.NoError(t, err)
	client.hostname = "oast.example"

	id := "abc123"
	url := id + "." + client.hostname
	data := &RequestData{
		Event: &output.InternalWrappedEvent{InternalEvent: map[string]interface{}{
			templateIdAttribute: "test-template",
			"host":              "example.com",
		}},
		Eviction: 50 * time.Millisecond,
	}

	client.RequestEvent([]string{url}, data)

	got, err := client.requests.Get(id)
	require.NoError(t, err)
	require.Equal(t, data, got)

	require.Eventually(t, func() bool {
		_, err := client.requests.Get(id)
		return err != nil
	}, time.Second, 10*time.Millisecond)
}
