package component

import (
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestPathNumericFuzzing(t *testing.T) {
	// Test case for issue #6398 - numeric path parts should be fuzzable
	req, err := retryablehttp.NewRequest("GET", "http://example.com/user/55/profile", nil)
	require.Nil(t, err, "could not create request")

	path := NewPath()
	ok, err := path.Parse(req)
	require.Nil(t, err, "could not parse path")
	require.True(t, ok, "path should be parseable")

	// Verify we can iterate over path segments
	segmentCount := 0
	err = path.Iterate(func(key string, value interface{}) error {
		segmentCount++
		t.Logf("Segment %s: %v (type: %T)", key, value, value)
		return nil
	})
	require.Nil(t, err, "could not iterate")
	require.Equal(t, 3, segmentCount, "expected 3 path segments")

	// Test fuzzing the numeric segment (key "2" = "55")
	// This should work even though "55" might be stored as an integer
	err = path.SetValue("2", "55 OR True")
	require.Nil(t, err, "should be able to fuzz numeric path segment")

	// Rebuild the request with the fuzzed value
	rebuilt, err := path.Rebuild()
	require.Nil(t, err, "could not rebuild request")

	// Verify the path contains the fuzzed value
	// Note: The path will be unescaped by the Rebuild method
	expectedPath := "/user/55 OR True/profile"
	require.Equal(t, expectedPath, rebuilt.Path, "fuzzed numeric value should be in path")
}
