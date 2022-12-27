package hosterrorscache

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheckMarkFailed(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	if failedTarget, err := cache.failedTargets.Get("http://example.com:80"); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
	}

	if failedTarget, err := cache.failedTargets.Get("example.com:80"); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
	}

	if failedTarget, err := cache.failedTargets.Get("example.com"); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
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

	hostValue := "http://asdasjkdashkjdahsjkdhas:80"

	if failedTarget, err := cache.failedTargets.Get(hostValue); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
	}

	existingCacheItem, err := cache.failedTargets.GetIFPresent(hostValue)
	if err == nil {
		skippingValue := false
		existingCacheItemValue := existingCacheItem.(*cacheItem)
		if existingCacheItemValue.errors.Load() >= int32(cache.MaxHostError) {
			skippingValue = true
		}
		require.Equal(t, true, skippingValue, "Didn't skipped host")
	}

	hostValue = "asdasjkdashkjdahsjkdhas:80"

	if failedTarget, err := cache.failedTargets.Get(hostValue); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
	}

	existingCacheItem, err = cache.failedTargets.GetIFPresent(hostValue)
	if err == nil {
		skippingValue := false
		existingCacheItemValue := existingCacheItem.(*cacheItem)
		if existingCacheItemValue.errors.Load() >= int32(cache.MaxHostError) {
			skippingValue = true
		}
		require.Equal(t, true, skippingValue, "Didn't skipped host")
	}

	hostValue = "asdasjkdashkjdahsjkdhas"

	if failedTarget, err := cache.failedTargets.Get(hostValue); err == nil && failedTarget != nil {
		if value, ok := failedTarget.(*cacheItem); ok {
			require.EqualValues(t, 1, value.errors.Load(), "could not get correct number of marked failed hosts")
		}
	}

	existingCacheItem, err = cache.failedTargets.GetIFPresent(hostValue)
	if err == nil {
		skippingValue := false
		existingCacheItemValue := existingCacheItem.(*cacheItem)
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
