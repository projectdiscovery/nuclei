package hosterrorscache

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheckMarkFailed(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	tests := []struct {
		host     string
		expected int
	}{
		{"http://example.com:80", 1},
		{"example.com:80", 2},
		{"example.com", 1},
	}

	for _, test := range tests {
		normalizedCacheValue := cache.normalizeCacheValue(test.host)
		cache.MarkFailed(test.host, fmt.Errorf("no address found for host"))
		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		value, ok := failedTarget.(*cacheItem)
		require.True(t, ok)
		require.EqualValues(t, test.expected, value.errors.Load())
	}

	for i := 0; i < 3; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCacheItemCheckMarkFailedMultipleCalls(t *testing.T) {
	t.Parallel()

	cache := New(3, DefaultMaxHostsCount)

	tests := []struct {
		host     string
		expected int
	}{
		{"http://asdasjkdashkjdahsjkdhas:80", 1},
		{"asdasjkdashkjdahsjkdhas:80", 2},
		{"asdasjkdashkjdahsjkdhas", 1},
	}

	for _, test := range tests {
		normalizedCacheValue := cache.normalizeCacheValue(test.host)
		cache.MarkFailed(test.host, fmt.Errorf("no address found for host"))
		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		skippingValue := false

		existingCacheItem, err := cache.failedTargets.GetIFPresent(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, existingCacheItem)
		existingCacheItemValue := existingCacheItem.(*cacheItem)
		require.NotNil(t, existingCacheItem)
		if existingCacheItemValue.errors.Load() >= int32(cache.MaxHostError) {
			skippingValue = true
		}
		require.Equal(t, true, skippingValue, "Didn't skipped host")
	}

	for i := 0; i < 3; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}
