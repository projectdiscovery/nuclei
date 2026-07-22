package json

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

type logRequestShape struct {
	Template  string      `json:"template"`
	Type      string      `json:"type"`
	Input     string      `json:"input"`
	Timestamp *string     `json:"timestamp,omitempty"`
	Address   string      `json:"address"`
	Error     string      `json:"error"`
	Kind      string      `json:"kind,omitempty"`
	Attrs     interface{} `json:"attrs,omitempty"`
}

func TestMarshalPreservesStructFieldOutputShape(t *testing.T) {
	output, err := Marshal(logRequestShape{
		Template: "path",
		Type:     "http",
		Input:    "input",
		Address:  "input:",
		Error:    "none",
	})
	require.NoError(t, err)
	require.Equal(t, `{"template":"path","type":"http","input":"input","address":"input:","error":"none"}`, string(output))
}

func TestEncoderAddsTrailingNewline(t *testing.T) {
	var buffer bytes.Buffer
	err := NewEncoder(&buffer).Encode(logRequestShape{
		Template: "path",
		Type:     "http",
		Input:    "input",
		Address:  "input:",
		Error:    "none",
	})
	require.NoError(t, err)
	require.Equal(t, "{\"template\":\"path\",\"type\":\"http\",\"input\":\"input\",\"address\":\"input:\",\"error\":\"none\"}\n", buffer.String())
}

func TestMarshalEscapesHTML(t *testing.T) {
	output, err := Marshal(map[string]string{"value": "<tag>&"})
	require.NoError(t, err)
	require.Equal(t, `{"value":"\u003ctag\u003e\u0026"}`, string(output))
}

func TestMapRoundTripPreservesDecodedValues(t *testing.T) {
	output, err := Marshal(map[string]interface{}{
		"foo":    "bar",
		"number": float64(2),
		"nested": map[string]interface{}{"ok": true},
	})
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, Unmarshal(output, &decoded))
	require.Equal(t, "bar", decoded["foo"])
	require.Equal(t, float64(2), decoded["number"])
	require.Equal(t, map[string]interface{}{"ok": true}, decoded["nested"])
}
