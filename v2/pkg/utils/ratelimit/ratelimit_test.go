package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateLimit(t *testing.T) {
	t.Run("Standard Rate Limit", func(t *testing.T) {
		expected := time.Duration(15 * time.Second)
		limiter := New(10, expected)
		require.NotNil(t, limiter)
		var count int
		start := time.Now()
		for i := 0; i < 10; i++ {
			limiter.Take()
			count++
		}
		took := time.Now().Sub(start)
		require.Equal(t, count, 10)
		require.True(t, took < expected)
		// take another one above max
		limiter.Take()
		took = time.Now().Sub(start)
		require.True(t, took >= expected)
	})

	t.Run("Unlimited Rate Limit", func(t *testing.T) {
		limiter := NewUnlimited()
		require.NotNil(t, limiter)
		var count int
		start := time.Now()
		for i := 0; i < 1000; i++ {
			limiter.Take()
			count++
		}
		took := start.Sub(time.Now())
		require.Equal(t, count, 1000)
		require.True(t, took < time.Duration(1*time.Second))
	})
}
