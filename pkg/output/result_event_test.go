package output

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func TestResultEventRequestIdentityJSONCompatibility(t *testing.T) {
	legacy := []byte(`{"template-id":"legacy","info":{"name":"legacy","author":["test"],"severity":"info"},"type":"http","matched-at":"https://example.com","matcher-status":true,"timestamp":"2026-01-01T00:00:00Z"}`)
	var decoded ResultEvent
	require.NoError(t, json.Unmarshal(legacy, &decoded))
	require.Equal(t, "legacy", decoded.TemplateID)
	require.Empty(t, decoded.RequestID)
	require.Empty(t, decoded.RequestBlockID)
	require.Zero(t, decoded.RequestProbeIndex)

	encoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "request-id")
	require.NotContains(t, string(encoded), "request-block-id")
	require.NotContains(t, string(encoded), "request-probe-index")

	decoded.RequestID = "ssl_2"
	decoded.RequestBlockID = "v1:ssl:explicit:certificate"
	decoded.RequestProbeIndex = 3
	encoded, err = json.Marshal(&decoded)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"request-id":"ssl_2"`)
	require.Contains(t, string(encoded), `"request-block-id":"v1:ssl:explicit:certificate"`)
	require.Contains(t, string(encoded), `"request-probe-index":3`)

	var roundTrip ResultEvent
	require.NoError(t, json.Unmarshal(encoded, &roundTrip))
	require.Equal(t, "ssl_2", roundTrip.RequestID)
	require.Equal(t, "v1:ssl:explicit:certificate", roundTrip.RequestBlockID)
	require.Equal(t, 3, roundTrip.RequestProbeIndex)
}

func TestCloneShallowKeepsRequestProbeIndex(t *testing.T) {
	event := &InternalWrappedEvent{InternalEvent: InternalEvent{"k": "v"}, RequestProbeIndex: 2}

	require.Equal(t, 2, event.CloneShallow().RequestProbeIndex)
}
