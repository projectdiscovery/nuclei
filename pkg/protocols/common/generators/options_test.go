package generators

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBuildPayloadFromOptionsConcurrency(t *testing.T) {
	// Test that BuildPayloadFromOptions is safe for concurrent use
	// and returns independent copies that can be modified without races
	vars := goflags.RuntimeMap{}
	_ = vars.Set("key=value")

	opts := &types.Options{
		Vars: vars,
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Each goroutine gets a map and modifies it
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Get the map (should be a copy of cached data)
			m := BuildPayloadFromOptions(opts)

			// Modify it - this should not cause races
			m["goroutine_id"] = id
			m["test_key"] = "test_value"

			// Verify original cached value is present
			require.Equal(t, "value", m["key"])
		}(i)
	}

	wg.Wait()
}

func TestBuildPayloadFromOptionsCaching(t *testing.T) {
	// Test that caching actually works
	vars := goflags.RuntimeMap{}
	_ = vars.Set("cached=yes")

	opts := &types.Options{
		Vars:                 vars,
		EnvironmentVariables: false,
	}

	// First call - builds and caches
	m1 := BuildPayloadFromOptions(opts)
	require.Equal(t, "yes", m1["cached"])

	// Second call - should return copy of cached result
	m2 := BuildPayloadFromOptions(opts)
	require.Equal(t, "yes", m2["cached"])

	// Modify m1 - should not affect m2 since they're copies
	m1["modified"] = "in_m1"
	require.NotContains(t, m2, "modified")

	// Modify m2 - should not affect future calls
	m2["modified"] = "in_m2"
	m3 := BuildPayloadFromOptions(opts)
	require.NotContains(t, m3, "modified")
}

func TestClearOptionsPayloadMap(t *testing.T) {
	vars := goflags.RuntimeMap{}
	_ = vars.Set("temp=data")

	opts := &types.Options{
		Vars: vars,
	}

	// Build and cache
	m1 := BuildPayloadFromOptions(opts)
	require.Equal(t, "data", m1["temp"])

	// Clear the cache
	ClearOptionsPayloadMap(opts)

	// Verify it still works (rebuilds)
	m2 := BuildPayloadFromOptions(opts)
	require.Equal(t, "data", m2["temp"])
}
