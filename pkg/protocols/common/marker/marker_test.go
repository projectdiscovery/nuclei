package marker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindInteractshURLMarkers(t *testing.T) {
	data := "a {{interactsh-url}} b %7B%7binteractsh-url_1_22_333%7d%7D c"

	require.Equal(t, []string{
		"{{interactsh-url}}",
		"%7B%7binteractsh-url_1_22_333%7d%7D",
	}, FindInteractshURLMarkers(data))
}

func TestHasInteractshURLMarkerRejectsMixedRawEncodedBraces(t *testing.T) {
	items := []string{
		"%7B{interactsh-url}}",
		"{{interactsh-url}%7D",
		"%7B%7Binteractsh-url}}",
		"{{interactsh-url%7D%7D",
	}

	for _, item := range items {
		t.Run(item, func(t *testing.T) {
			require.False(t, HasInteractshURLMarker(item))
		})
	}
}

func TestHasInteractshURLMarkerRejectsMalformedSuffixes(t *testing.T) {
	items := []string{
		"{{interactsh-url_}}",
		"{{interactsh-url_a}}",
		"{{interactsh-url_1_2_3_4}}",
	}

	for _, item := range items {
		t.Run(item, func(t *testing.T) {
			require.False(t, HasInteractshURLMarker(item))
		})
	}
}
