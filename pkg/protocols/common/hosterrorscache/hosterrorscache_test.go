package hosterrorscache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheck(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

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

func TestTrackErrors(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, []string{"custom error"})

	for i := 0; i < 100; i++ {
		cache.MarkFailed("custom", fmt.Errorf("got: nested: custom error"))
		got := cache.Check("custom")
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}
	value := cache.Check("custom")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCacheItemDo(t *testing.T) {
	var (
		count int
		item  cacheItem
	)

	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
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
	cache := New(3, DefaultMaxHostsCount, nil)

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

func TestCacheMarkFailedConcurrent(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	tests := []struct {
		host     string
		expected int32
	}{
		{"http://example.com:80", 200},
		{"example.com:80", 200},
		{"example.com", 100},
	}

	// the cache is not atomic during items creation, so we pre-create them with counter to zero
	for _, test := range tests {
		normalizedValue := cache.normalizeCacheValue(test.host)
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(0)
		_ = cache.failedTargets.Set(normalizedValue, newItem)
	}

	wg := sync.WaitGroup{}
	for _, test := range tests {
		currentTest := test
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.MarkFailed(currentTest.host, fmt.Errorf("could not resolve host"))
			}()
		}
	}
	wg.Wait()

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
