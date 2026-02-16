package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestURLComponent verifies basic path parsing, iteration, and rebuilding logic.
func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	require.NoError(t, err)

	urlComponent := NewPath()
	_, err = urlComponent.Parse(req)
	require.NoError(t, err)

	var keys []string
	var values []string
	err = urlComponent.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})
	require.NoError(t, err)

	require.Equal(t, []string{"1"}, keys, "unexpected keys")
	require.Equal(t, []string{"testpath"}, values, "unexpected values")

	err = urlComponent.SetValue("1", "newpath")
	require.NoError(t, err)

	rebuilt, err := urlComponent.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/newpath", rebuilt.Path, "unexpected URL path")
	require.Equal(t, "https://example.com/newpath", rebuilt.String(), "unexpected full URL")
}

// TestURLComponent_NestedPaths validates the component's ability to handle and modify
// multiple nested path segments.
func TestURLComponent_NestedPaths(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/753/profile", nil)
	require.NoError(t, err)

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found, "expected path to be found")

	isSet := false
	err = path.Iterate(func(key string, value interface{}) error {
		t.Logf("Key: %s, Value: %s", key, value.(string))
		if !isSet && value.(string) == "753" {
			isSet = true
			if setErr := path.SetValue(key, "753'"); setErr != nil {
				return setErr
			}
		}
		return nil
	})
	require.NoError(t, err)

	newReq, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/user/753'/profile", newReq.Path, "expected modified path mismatch")
}

// TestPathComponent_SQLInjection ensures that spaces and special characters used in
// SQL injection payloads are correctly preserved in the rebuilt path.
func TestPathComponent_SQLInjection(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found, "expected path to be found")

	err = path.Iterate(func(key string, value interface{}) error {
		if value.(string) == "55" {
			if setErr := path.SetValue(key, "55 OR True"); setErr != nil {
				return setErr
			}
		}
		return nil
	})
	require.NoError(t, err)

	newReq, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/user/55 OR True/profile", newReq.Path, "SQL injection payload corruption")
}

// TestPathComponent_Determinism addresses issue #6398 by verifying that path
// iteration remains 100% deterministic across multiple parsing cycles.
func TestPathComponent_Determinism(t *testing.T) {
	pathStr := "/user/55/profile/settings/12345"
	// Fix: Captured and validated error from NewRequest
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com"+pathStr, nil)
	require.NoError(t, err)

	expected := []string{"user", "55", "profile", "settings", "12345"}

	// Run multiple times to ensure Go's map randomization doesn't affect the order
	for i := 0; i < 100; i++ {
		p := NewPath()
		found, err := p.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		var results []string
		// Fix: Captured and validated error from Iterate
		err = p.Iterate(func(key string, value interface{}) error {
			results = append(results, value.(string))
			return nil
		})
		require.NoError(t, err)

		require.Equal(t, expected, results, "Non-deterministic order at iteration %d", i)
	}
}
