package hosterrorscache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheckMarkFailed(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	cache.MarkFailed("http://example.com:80")
	if value, err := cache.failedTargets.Get("http://example.com:80"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com:80")
	if value, err := cache.failedTargets.Get("example.com:80"); err == nil && value != nil {
		require.Equal(t, 2, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com")
	if value, err := cache.failedTargets.Get("example.com"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	for i := 0; i < 3; i++ {
		cache.MarkFailed("test")
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}
