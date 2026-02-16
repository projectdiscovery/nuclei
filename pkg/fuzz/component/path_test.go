package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestURLComponent verifies basic path parsing, mutation, and rebuilding logic.
func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	require.NoError(t, err)

	urlComponent := NewPath()
	_, err = urlComponent.Parse(req)
	require.NoError(t, err)

	// 1. Verify initial deterministic iteration
	var keys []string
	err = urlComponent.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"1"}, keys)

	// 2. Test Mutation (The CodeRabbit nitpick)
	err = urlComponent.SetValue("1", "fuzzed-path")
	require.NoError(t, err)

	// 3. Test Rebuild
	rebuilt, err := urlComponent.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/fuzzed-path", rebuilt.URL.Path)
	require.Equal(t, "https://example.com/fuzzed-path", rebuilt.String())
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

// TestPathComponent_Delete verifies that deleting a segment preserves the order of remaining segments.
func TestPathComponent_Delete(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/a/b/c/d", nil)
	require.NoError(t, err)

	p := NewPath()
	_, err = p.Parse(req)
	require.NoError(t, err)

	// Eliminiamo il secondo segmento ("b") che ha chiave "2"
	err = p.Delete("2")
	require.NoError(t, err)

	// Verifichiamo che l'ordine dei segmenti rimanenti sia [a, c, d]
	expected := []string{"a", "c", "d"}
	var results []string
	err = p.Iterate(func(key string, value interface{}) error {
		results = append(results, value.(string))
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, expected, results, "The order of segments after deletion is not deterministic")

	// Verifichiamo che il Rebuild generi il path corretto senza "b"
	rebuilt, err := p.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/a/c/d", rebuilt.URL.Path)
}
