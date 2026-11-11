package replay

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func TestEventRoundTripKeepsWhatMatchersRead(t *testing.T) {
	event := output.InternalEvent{
		"body":        "<title>admin</title>",
		"raw":         "\x00\xffBIN\xfe",
		"data":        []byte{0, 1, 2},
		"status_code": 200,
		"answer":      []string{"a", "b"},
		"duration":    1.5,
		"matched":     true,
		"info":        map[string]any{"name": "x"},
		"callback":    func() {},
	}
	data, err := json.Marshal(encodeEvent(event))
	require.NoError(t, err)
	var raw map[string]json.Message
	require.NoError(t, json.Unmarshal(data, &raw))
	decoded, err := decodeEvent(raw)
	require.NoError(t, err)

	require.Equal(t, "<title>admin</title>", decoded["body"])
	require.Equal(t, "\x00\xffBIN\xfe", decoded["raw"], "binary responses keep every byte")
	require.Equal(t, []byte{0, 1, 2}, decoded["data"])
	require.Equal(t, 200, decoded["status_code"], "the status matcher reads an int")
	require.Equal(t, []string{"a", "b"}, decoded["answer"])
	require.Equal(t, 1.5, decoded["duration"])
	require.Equal(t, true, decoded["matched"])
	require.Equal(t, map[string]any{"name": "x"}, decoded["info"])
	require.NotContains(t, decoded, "callback", "values JSON cannot hold are dropped")
}
