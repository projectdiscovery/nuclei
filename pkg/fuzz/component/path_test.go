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

// TestPathComponent_RebuildDoesNotMutateOriginal verifies that Rebuild()
// does not mutate the original request path, which caused numeric path
// segments to be skipped when fuzzing in single mode (issue #6398).
func TestPathComponent_RebuildDoesNotMutateOriginal(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found)

	// Simulate single-mode fuzzing: fuzz each segment one at a time,
	// rebuilding after each and then resetting.
	segments := map[string]string{}
	_ = path.Iterate(func(key string, value interface{}) error {
		segments[key] = value.(string)
		return nil
	})

	var fuzzedPaths []string
	for key, original := range segments {
		err := path.SetValue(key, original+"%20FUZZED")
		require.NoError(t, err)

		rebuilt, err := path.Rebuild()
		require.NoError(t, err)
		fuzzedPaths = append(fuzzedPaths, rebuilt.Path)

		// Reset value back to original
		err = path.SetValue(key, original)
		require.NoError(t, err)
	}

	// All three segments must have been fuzzed
	require.Len(t, fuzzedPaths, 3, "expected 3 fuzzed paths for 3 segments")

	// Verify that each segment was individually fuzzed
	require.Contains(t, fuzzedPaths, "/user FUZZED/55/profile")
	require.Contains(t, fuzzedPaths, "/user/55 FUZZED/profile")
	require.Contains(t, fuzzedPaths, "/user/55/profile FUZZED")
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
