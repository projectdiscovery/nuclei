package hosterrorscache

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheckMarkFailed(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount)

	cache.MarkFailed("http://example.com:80", fmt.Errorf("no address found for host"))
	if value, err := cache.failedTargets.Get("http://example.com:80"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com:80", fmt.Errorf("Client.Timeout exceeded while awaiting headers"))
	if value, err := cache.failedTargets.Get("example.com:80"); err == nil && value != nil {
		require.Equal(t, 2, value, "could not get correct number of marked failed hosts")
	}
	cache.MarkFailed("example.com", fmt.Errorf("could not resolve host"))
	if value, err := cache.failedTargets.Get("example.com"); err == nil && value != nil {
		require.Equal(t, 1, value, "could not get correct number of marked failed hosts")
	}
	for i := 0; i < 3; i++ {
		cache.MarkFailed("test", fmt.Errorf("could not resolve host"))
	}

	value := cache.Check("test")
	require.Equal(t, true, value, "could not get checked value")
}
