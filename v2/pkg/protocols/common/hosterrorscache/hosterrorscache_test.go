package hosterrorscache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheck(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	for i := 0; i < 3; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCacheMarkFailed(t *testing.T) {
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
}

func TestCacheMarkFailedMultipleCalls(t *testing.T) {
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

		existingCacheItem, err := cache.failedTargets.GetIFPresent(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, existingCacheItem)
		existingCacheItemValue := existingCacheItem.(*cacheItem)
		skippingValue := existingCacheItemValue.errors.Load() >= int32(test.expected)
		require.Equal(t, true, skippingValue, "Didn't skipped host")
	}
}

func TestCacheMarkFailedConcurrent(t *testing.T) {
	t.Parallel()

	cache := New(3, DefaultMaxHostsCount)

	tests := []struct {
		host     string
		expected int32
	}{
		{"http://example.com:80", 5},
		{"example.com:80", 10},
		{"example.com", 5},
	}

	for _, test := range tests {
		normalizedCacheValue := cache.normalizeCacheValue(test.host)
		wg := sync.WaitGroup{}
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				cache.MarkFailed(normalizedCacheValue, fmt.Errorf("could not resolve host"))
				wg.Done()
			}()
		}
		wg.Wait()

		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		value, ok := failedTarget.(*cacheItem)
		require.True(t, ok)
		require.EqualValues(t, test.expected, value.errors.Load())
	}
}
