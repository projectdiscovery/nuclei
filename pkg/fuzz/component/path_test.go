package component

import (
	"fmt"
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

// TestPathComponent_NumericSegmentOrder verifies that numeric path segments
// are iterated in insertion order, not random map order. This is the core
// regression test for https://github.com/projectdiscovery/nuclei/issues/6398
func TestPathComponent_NumericSegmentOrder(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)

	// Run the test multiple times to catch non-deterministic ordering
	for i := 0; i < 50; i++ {
		path := NewPath()
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

		require.Equal(t, []string{"1", "2", "3"}, keys, "iteration %d: keys must be in insertion order", i)
		require.Equal(t, []string{"user", "55", "profile"}, values, "iteration %d: values must be in insertion order", i)
	}
}

// TestPathComponent_FuzzAllSegments verifies that every path segment,
// including numeric ones, is fuzzed exactly once.
func TestPathComponent_FuzzAllSegments(t *testing.T) {
	expectedPaths := []string{
		"/blog FUZZ/post",
		"/blog/post FUZZ",
	}

	for idx, expected := range expectedPaths {
		// Create a fresh request for each iteration to avoid any shared state
		iterReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/blog/post", nil)
		require.NoError(t, err)

		path := NewPath()
		found, err := path.Parse(iterReq)
		require.NoError(t, err)
		require.True(t, found)

		// Collect keys and values first, then fuzz only the target segment
		var keys []string
		var values []string
		err = path.Iterate(func(key string, value interface{}) error {
			keys = append(keys, key)
			values = append(values, value.(string))
			return nil
		})
		require.NoError(t, err)

		err = path.SetValue(keys[idx], fmt.Sprintf("%s FUZZ", values[idx]))
		require.NoError(t, err)

		rebuilt, err := path.Rebuild()
		require.NoError(t, err)
		require.Equal(t, expected, rebuilt.Path, "segment %d not fuzzed correctly", idx)
	}
}

// TestPathComponent_NumericOnlySegments verifies paths where all segments
// are numeric (the exact scenario from issue #6398).
func TestPathComponent_NumericOnlySegments(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/123/456/789", nil)
	require.NoError(t, err)

	path := NewPath()
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

	require.Equal(t, []string{"1", "2", "3"}, keys, "keys must be in order")
	require.Equal(t, []string{"123", "456", "789"}, values, "numeric values must be preserved as strings in order")

	// Fuzz the middle numeric segment
	err = path.SetValue("2", "456 OR True")
	require.NoError(t, err)

	rebuilt, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/123/456 OR True/789", rebuilt.Path)
}
