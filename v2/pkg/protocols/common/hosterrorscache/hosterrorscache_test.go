package hosterrorscache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func markFailedConcurrently(cache *Cache, host string, numCalls int) {
	wg := sync.WaitGroup{}
	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.MarkFailed(host, fmt.Errorf("could not resolve host"))
		}()
	}
	wg.Wait()
}

func TestCacheCheck(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	for i := 0; i < 100; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
		got := cache.Check("test")
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCacheItemDo(t *testing.T) {
	t.Parallel()

	var (
		count int
		item  cacheItem
	)

	wg := sync.WaitGroup{}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item.Do(func() {
				count++
			})
		}()
	}
	wg.Wait()

	// ensures the increment happened only once regardless of the multiple call
	require.Equal(t, count, 1)
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
		{"http://example.com:80", 200},
		{"example.com:80", 200},
		{"example.com", 100},
	}

	for _, test := range tests {
		markFailedConcurrently(cache, test.host, 100)
	}

	for _, test := range tests {
		require.True(t, cache.Check(test.host))

		normalizedCacheValue := cache.normalizeCacheValue(test.host)
		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		value, ok := failedTarget.(*cacheItem)
		require.True(t, ok)
		require.EqualValues(t, test.expected, value.errors.Load())
	}
}
