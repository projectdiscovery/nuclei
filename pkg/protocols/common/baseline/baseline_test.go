package baseline

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetOrFetchCachesPerHost(t *testing.T) {
	cache := New()
	var calls atomic.Int32
	fetch := func() (Map, error) {
		calls.Add(1)
		return Map{"status_code": 200}, nil
	}

	for i := 0; i < 5; i++ {
		data, ok := cache.GetOrFetch("https://example.com", fetch)
		require.True(t, ok)
		require.Equal(t, 200, data["status_code"])
	}
	require.Equal(t, int32(1), calls.Load(), "baseline should be fetched once per host")

	cache.GetOrFetch("https://other.com", fetch)
	require.Equal(t, int32(2), calls.Load(), "distinct host should trigger a new fetch")
}

func TestGetOrFetchFetchesOnceUnderConcurrency(t *testing.T) {
	cache := New()
	var calls atomic.Int32
	fetch := func() (Map, error) {
		calls.Add(1)
		return Map{"ok": true}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.GetOrFetch("https://example.com", fetch)
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), calls.Load(), "concurrent access must fetch the baseline exactly once")
}

func TestGetOrFetchErrorNotCached(t *testing.T) {
	cache := New()
	_, ok := cache.GetOrFetch("https://example.com", func() (Map, error) {
		return nil, errors.New("boom")
	})
	require.False(t, ok, "failed fetch should report no usable baseline")
}

func TestGetOrFetchNilReceiverOrEmptyHost(t *testing.T) {
	var cache *Cache
	_, ok := cache.GetOrFetch("https://example.com", func() (Map, error) { return Map{}, nil })
	require.False(t, ok)

	cache = New()
	_, ok = cache.GetOrFetch("", func() (Map, error) { return Map{}, nil })
	require.False(t, ok)
}
