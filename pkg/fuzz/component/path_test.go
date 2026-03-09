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
// always iterated in their original order, not in random map order.
// This is a regression test for https://github.com/projectdiscovery/nuclei/issues/6398
func TestPathComponent_DeterministicIteration(t *testing.T) {
	// Run multiple iterations to catch non-deterministic behavior.
	// With a regular Go map, the order is randomized and this test
	// would fail intermittently (~50% of runs with 3+ segments).
	for run := 0; run < 50; run++ {
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

		require.Equal(t, []string{"1", "2", "3"}, keys,
			"run %d: path segment keys must be in insertion order", run)
		require.Equal(t, []string{"user", "55", "profile"}, values,
			"run %d: path segment values must match original path order", run)
	}
}

// TestPathComponent_NumericSegmentFuzzing verifies that every path segment
// (including numeric ones like "55") is visited and can be fuzzed.
// Regression test for https://github.com/projectdiscovery/nuclei/issues/6398
func TestPathComponent_NumericSegmentFuzzing(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		segments []string
	}{
		{"simple numeric", "https://example.com/user/55/profile", []string{"user", "55", "profile"}},
		{"multiple numeric", "https://example.com/api/v2/users/123/posts/456", []string{"api", "v2", "users", "123", "posts", "456"}},
		{"all numeric", "https://example.com/1/2/3/4/5", []string{"1", "2", "3", "4", "5"}},
		{"single segment", "https://example.com/test", []string{"test"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for run := 0; run < 20; run++ {
				path := NewPath()
				req, err := retryablehttp.NewRequest(http.MethodGet, tc.url, nil)
				require.NoError(t, err)

				found, err := path.Parse(req)
				require.NoError(t, err)
				require.True(t, found)

				// Verify all segments are present and in order
				var values []string
				err = path.Iterate(func(key string, value interface{}) error {
					values = append(values, value.(string))
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, tc.segments, values,
					"run %d: segments must be in original path order", run)

				// Verify each segment can be individually fuzzed
				for i, seg := range tc.segments {
					fuzzPath := path.Clone().(*Path)
					key := fmt.Sprintf("%d", i+1)
					err := fuzzPath.SetValue(key, seg+"'")
					require.NoError(t, err)

					rebuilt, err := fuzzPath.Rebuild()
					require.NoError(t, err)
					require.Contains(t, rebuilt.Path, seg+"'",
						"fuzzed segment %q (key %s) must appear in rebuilt path", seg, key)
				}
			}
		})
	}
}
