package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	if err != nil {
		t.Fatal(err)
	}

	urlComponent := NewPath()
	_, err = urlComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = urlComponent.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.Equal(t, []string{"1"}, keys, "unexpected keys")
	require.Equal(t, []string{"testpath"}, values, "unexpected values")

	err = urlComponent.SetValue("1", "newpath")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := urlComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "/newpath", rebuilt.Path, "unexpected URL path")
	require.Equal(t, "https://example.com/newpath", rebuilt.String(), "unexpected full URL")
}

func TestURLComponent_NestedPaths(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/753/profile", nil)
	if err != nil {
		t.Fatal(err)
	}
	found, err := path.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected path to be found")
	}

	isSet := false

	_ = path.Iterate(func(key string, value interface{}) error {
		t.Logf("Key: %s, Value: %s", key, value.(string))
		if !isSet && value.(string) == "753" {
			isSet = true
			if setErr := path.SetValue(key, "753'"); setErr != nil {
				t.Fatal(setErr)
			}
		}
		return nil
	})

	newReq, err := path.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if newReq.Path != "/user/753'/profile" {
		t.Fatalf("expected path to be '/user/753'/profile', got '%s'", newReq.Path)
	}
}

func TestPathComponent_SQLInjection(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	if err != nil {
		t.Fatal(err)
	}
	found, err := path.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected path to be found")
	}

	t.Logf("Original path: %s", req.Path)

	// Let's see what path segments are available for fuzzing
	err = path.Iterate(func(key string, value interface{}) error {
		t.Logf("Key: %s, Value: %s", key, value.(string))

		// Try fuzzing the "55" segment specifically (which should be key "2")
		if value.(string) == "55" {
			if setErr := path.SetValue(key, "55 OR True"); setErr != nil {
				t.Fatal(setErr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	newReq, err := path.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Modified path: %s", newReq.Path)

	// Now with PathEncode, spaces are preserved correctly for SQL injection
	if newReq.Path != "/user/55 OR True/profile" {
		t.Fatalf("expected path to be '/user/55 OR True/profile', got '%s'", newReq.Path)
	}

	// Let's also test what the actual URL looks like
	t.Logf("Full URL: %s", newReq.String())
}

// TestPathComponent_DeterministicIteration verifies that path segment iteration order is deterministic
// by running 100 iterations and ensuring keys and values are always returned in the same order.
// This test validates the fix that replaced standard maps with OrderedMap to ensure consistent
// fuzzing behavior across multiple executions.
func TestPathComponent_DeterministicIteration(t *testing.T) {
	// Run the test 100 times to catch non-deterministic behavior
	for iteration := 0; iteration < 100; iteration++ {
		path := NewPath()
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
		require.NoError(t, err)

		found, err := path.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		var keys []string
		var values []string

		err = path.Iterate(func(key string, value interface{}) error {
			keys = append(keys, key)
			values = append(values, value.(string))
			return nil
		})
		require.NoError(t, err)

		// Keys and values should always be in the same order
		expectedKeys := []string{"1", "2", "3"}
		expectedValues := []string{"user", "55", "profile"}

		require.Equal(t, expectedKeys, keys, "iteration %d: keys should be deterministic", iteration)
		require.Equal(t, expectedValues, values, "iteration %d: values should be deterministic", iteration)
	}
}
