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

func TestPath_NumericSegments(t *testing.T) {
	// Test case for issue #6398 - Fuzzing should not skip numeric path parts
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)
	
	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found, "expected path to be found")
	
	// Verify all 3 segments are parsed: user, 55, profile
	segments := make(map[string]string)
	_ = path.Iterate(func(key string, value interface{}) error {
		segments[key] = value.(string)
		t.Logf("Segment %s: %s", key, value.(string))
		return nil
	})
	
	require.Equal(t, 3, len(segments), "should have 3 path segments")
	require.Equal(t, "user", segments["1"], "segment 1 should be 'user'")
	require.Equal(t, "55", segments["2"], "segment 2 should be '55' (numeric)")
	require.Equal(t, "profile", segments["3"], "segment 3 should be 'profile'")
	
	// Test fuzzing the numeric segment (55)
	err = path.SetValue("2", "55 OR True")
	require.NoError(t, err)
	
	newReq, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/user/55 OR True/profile", newReq.Path, "should fuzz numeric segment")
	
	t.Logf("Fuzzed URL: %s", newReq.String())
}

func TestPath_MultipleNumericSegments(t *testing.T) {
	// Test with multiple numeric segments
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/api/v1/users/123/posts/456", nil)
	require.NoError(t, err)
	
	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found)
	
	// Count segments
	count := 0
	_ = path.Iterate(func(key string, value interface{}) error {
		count++
		t.Logf("Segment %s: %s", key, value.(string))
		return nil
	})
	
	require.Equal(t, 6, count, "should have 6 segments: api, v1, users, 123, posts, 456")
	
	// Fuzz first numeric segment (v1)
	err = path.SetValue("2", "v2")
	require.NoError(t, err)
	
	// Fuzz second numeric segment (123)
	err = path.SetValue("4", "999")
	require.NoError(t, err)
	
	// Fuzz third numeric segment (456)
	err = path.SetValue("6", "789")
	require.NoError(t, err)
	
	newReq, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/api/v2/users/999/posts/789", newReq.Path, "should fuzz all numeric segments")
}
