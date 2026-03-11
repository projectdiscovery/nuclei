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

func TestPathComponent_DeterministicOrder(t *testing.T) {
	for i := 0; i < 50; i++ {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
		require.NoError(t, err)

		path := NewPath()
		found, err := path.Parse(req)
		require.NoError(t, err)
		require.True(t, found)

		var values []string
		err = path.Iterate(func(_ string, value interface{}) error {
			values = append(values, value.(string))
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, []string{"user", "55", "profile"}, values,
			"iteration %d: path segments must be returned in deterministic order", i)
	}
}

func TestPathComponent_RebuildUsesOriginalPathSnapshot(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found)

	// Capture original path before any mutations
	originalPath := req.Path

	require.NoError(t, path.SetValue("3", "profile OR True"))
	newReq, err := path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/user/55/profile OR True", newReq.Path)
	require.Equal(t, originalPath, req.Path, "original request path should remain unchanged after Rebuild")

	// Rebuilding after a prior mutation should still use the original path layout
	// without mutating the original request.
	require.NoError(t, path.SetValue("3", "profile"))
	require.NoError(t, path.SetValue("2", "55 OR True"))
	newReq, err = path.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "/user/55 OR True/profile", newReq.Path)
	require.Equal(t, originalPath, req.Path, "original request path should remain unchanged after multiple Rebuilds")
}

func TestPathComponent_NumericSegmentsAllFuzzed(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		wantKeys []string
		wantVals []string
	}{
		{
			name:     "numeric ID in middle",
			url:      "https://example.com/user/55/profile",
			wantKeys: []string{"1", "2", "3"},
			wantVals: []string{"user", "55", "profile"},
		},
		{
			name:     "multiple numeric segments",
			url:      "https://example.com/api/123/items/456",
			wantKeys: []string{"1", "2", "3", "4"},
			wantVals: []string{"api", "123", "items", "456"},
		},
		{
			name:     "version and numeric ID",
			url:      "https://example.com/api/v2/users/789/orders",
			wantKeys: []string{"1", "2", "3", "4", "5"},
			wantVals: []string{"api", "v2", "users", "789", "orders"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := retryablehttp.NewRequest(http.MethodGet, tc.url, nil)
			require.NoError(t, err)

			path := NewPath()
			found, err := path.Parse(req)
			require.NoError(t, err)
			require.True(t, found)

			var gotKeys, gotVals []string
			err = path.Iterate(func(key string, value interface{}) error {
				gotKeys = append(gotKeys, key)
				gotVals = append(gotVals, value.(string))
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantKeys, gotKeys, "unexpected keys for %s", tc.url)
			require.Equal(t, tc.wantVals, gotVals, "unexpected values for %s", tc.url)
		})
	}
}
