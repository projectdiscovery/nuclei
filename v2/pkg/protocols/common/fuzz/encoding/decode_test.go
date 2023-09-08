package encoding

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeEncode(t *testing.T) {
	origStr := "eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6IjhqWTdYWmlNRW50cjhPdWInIn0%3D"

	decoded, err := Decode(origStr)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "{\"type\":\"class\",\"value\":\"8jY7XZiMEntr8Oub'\"}", decoded.Data, "could not get correct data")

	if len(decoded.Encoders) != 2 {
		t.Errorf("expected 2 encoder, got %d", len(decoded.Encoders))
	}
	require.ElementsMatch(t, []string{"url", "base64"}, decoded.Encoders)

	encoded := decoded.Encode(decoded.Data)
	if origStr != encoded {
		t.Errorf("expected %s, got %s", origStr, encoded)
	}
}
