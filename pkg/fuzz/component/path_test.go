package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestURLComponent verifies basic path parsing and rebuilding logic.
func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	require.NoError(t, err)

	urlComponent := NewPath()
	_, err = urlComponent.Parse(req)
	require.NoError(t, err)

	var keys []string
	err = urlComponent.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"1"}, keys)
}

// TestPathComponent_Determinism ensures that path iteration remains deterministic across 100 cycles.
func TestPathComponent_Determinism(t *testing.T) {
	pathStr := "/user/55/profile/settings/12345"
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com"+pathStr, nil)
	require.NoError(t, err)

	expected := []string{"user", "55", "profile", "settings", "12345"}

	for i := 0; i < 100; i++ {
		p := NewPath()
		found, err := p.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		var results []string
		err = p.Iterate(func(key string, value interface{}) error {
			results = append(results, value.(string))
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, expected, results)
	}
}
