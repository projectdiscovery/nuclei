package hosterrorscache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

const (
	protoType = "http"
)

func TestCacheCheck(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	for i := 0; i < 100; i++ {
		cache.MarkFailed(protoType, newCtxArgs("test"), fmt.Errorf("could not resolve host"))
		got := cache.Check(protoType, newCtxArgs("test"))
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}

	value := cache.Check(protoType, newCtxArgs("test"))
	require.Equal(t, true, value, "could not get checked value")
}

func TestTrackErrors(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, []string{"custom error"})

	for i := 0; i < 100; i++ {
		cache.MarkFailed(protoType, newCtxArgs("custom"), fmt.Errorf("got: nested: custom error"))
		got := cache.Check(protoType, newCtxArgs("custom"))
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}
	value := cache.Check(protoType, newCtxArgs("custom"))
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
		expected int32
	}{
		{"http://example.com:80", 1},
		{"example.com:80", 2},
		// earlier if port is not provided then port was omitted
		// but from now it will default to appropriate http scheme based port with 80 as default
		{"example.com:443", 1},
	}

	for _, test := range tests {
		normalizedCacheValue := cache.GetKeyFromContext(newCtxArgs(test.host), nil)
		cache.MarkFailed(protoType, newCtxArgs(test.host), fmt.Errorf("no address found for host"))
		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		require.EqualValues(t, test.expected, failedTarget.errors.Load())
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
		{"example.com:443", 100},
	}

	// the cache is not atomic during items creation, so we pre-create them with counter to zero
	for _, test := range tests {
		normalizedValue := cache.NormalizeCacheValue(test.host)
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
				cache.MarkFailed(protoType, newCtxArgs(currentTest.host), fmt.Errorf("could not resolve host"))
			}()
		}
	}
	wg.Wait()

	for _, test := range tests {
		require.True(t, cache.Check(protoType, newCtxArgs(test.host)))

		normalizedCacheValue := cache.NormalizeCacheValue(test.host)
		failedTarget, err := cache.failedTargets.Get(normalizedCacheValue)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		require.EqualValues(t, test.expected, failedTarget.errors.Load())
	}
}

func newCtxArgs(value string) *contextargs.Context {
	ctx := contextargs.NewWithInput(context.TODO(), value)
	return ctx
}
