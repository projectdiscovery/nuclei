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

// TestPathComponent_DeterministicIteration verifies that path segments are
// iterated in insertion order (1, 2, 3, ...) every time, not in random map
// order. This is the regression test for issue #6398 where numeric path
// parts like "55" in /user/55/profile were non-deterministically skipped
// during fuzzing because the underlying storage was a plain Go map.
func TestPathComponent_DeterministicIteration(t *testing.T) {
	const url = "https://example.com/user/55/profile/edit"
	expectedKeys := []string{"1", "2", "3", "4"}
	expectedVals := []string{"user", "55", "profile", "edit"}

	// Run enough iterations to surface random map ordering if present.
	// With 4 keys a plain map produces the correct order ~1/24 of the
	// time, so 100 iterations gives >99.99% chance of catching it.
	for i := 0; i < 100; i++ {
		req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)

		p := NewPath()
		found, err := p.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		var keys, vals []string
		_ = p.Iterate(func(key string, value interface{}) error {
			keys = append(keys, key)
			vals = append(vals, fmt.Sprint(value))
			return nil
		})

		require.Equal(t, expectedKeys, keys, "iteration %d: keys out of order", i)
		require.Equal(t, expectedVals, vals, "iteration %d: values out of order", i)
	}
}

// TestPathComponent_NumericSegmentFuzz verifies that every path segment,
// including purely numeric ones, gets fuzzed when iterating in single mode.
// This directly reproduces the scenario from issue #6398.
func TestPathComponent_NumericSegmentFuzz(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
		require.NoError(t, err)

		p := NewPath()
		found, err := p.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		// Simulate single-mode fuzzing: iterate, fuzz one segment, rebuild, restore.
		var rebuiltPaths []string
		var allKeys []string
		_ = p.Iterate(func(key string, value interface{}) error {
			allKeys = append(allKeys, key)
			orig := fmt.Sprint(value)
			err := p.SetValue(key, orig+" OR True")
			require.NoError(t, err)

			rebuilt, err := p.Rebuild()
			require.NoError(t, err)
			rebuiltPaths = append(rebuiltPaths, rebuilt.Path)

			// restore original
			err = p.SetValue(key, orig)
			require.NoError(t, err)
			return nil
		})

		require.Equal(t, []string{"1", "2", "3"}, allKeys,
			"iteration %d: not all segments iterated", iter)
		require.Contains(t, rebuiltPaths, "/user OR True/55/profile",
			"iteration %d: segment 'user' not fuzzed", iter)
		require.Contains(t, rebuiltPaths, "/user/55 OR True/profile",
			"iteration %d: numeric segment '55' not fuzzed", iter)
		require.Contains(t, rebuiltPaths, "/user/55/profile OR True",
			"iteration %d: segment 'profile' not fuzzed", iter)
	}
}
