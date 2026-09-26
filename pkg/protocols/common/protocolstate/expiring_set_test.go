package protocolstate

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpiringSetContainsAndExpires(t *testing.T) {
	set := NewExpiringSet(time.Minute)
	now := time.Now()
	set.StoreUntil("active", now.Add(time.Minute))
	set.StoreUntil("expired", now.Add(-time.Second))

	require.True(t, set.containsAt("active", now))
	require.False(t, set.containsAt("expired", now))
	_, exists := set.values.Load("expired")
	require.False(t, exists)
}

func TestExpiringSetKeysSortsAndCleans(t *testing.T) {
	set := NewExpiringSet(time.Minute)
	now := time.Now()
	set.StoreUntil("b", now.Add(time.Minute))
	set.StoreUntil("a", now.Add(time.Minute))
	set.StoreUntil("expired", now.Add(-time.Second))

	require.Equal(t, []string{"a", "b"}, set.keysAt(now))
	_, exists := set.values.Load("expired")
	require.False(t, exists)
}

func TestExpiringSetRefreshesTTL(t *testing.T) {
	set := NewExpiringSet(time.Minute)
	now := time.Now()
	set.StoreUntil("host", now.Add(time.Minute))
	set.StoreUntil("host", now.Add(2*time.Minute))

	require.True(t, set.containsAt("host", now.Add(90*time.Second)))
	require.False(t, set.containsAt("host", now.Add(3*time.Minute)))
}

func TestExpiringSetEmptyAndNil(t *testing.T) {
	var nilSet *ExpiringSet
	require.False(t, nilSet.Contains("host"))
	require.Empty(t, nilSet.Keys())

	set := NewExpiringSet(time.Minute)
	set.Store("", time.Minute)
	require.False(t, set.Contains(""))
	require.Empty(t, set.Keys())
}

func TestExpiringSetConcurrentAccess(t *testing.T) {
	set := NewExpiringSet(time.Minute)
	var done atomic.Int64

	t.Run("parallel", func(t *testing.T) {
		for i := range 100 {
			i := i
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				key := fmt.Sprintf("host-%d", i%10)
				set.Store(key, time.Minute)
				require.True(t, set.Contains(key))
				done.Add(1)
			})
		}
	})
	require.Equal(t, int64(100), done.Load())
}

func TestExpiringSetConcurrentRefreshSurvivesExpiredCleanup(t *testing.T) {
	for range 1000 {
		set := NewExpiringSet(time.Minute)
		now := time.Now()
		set.StoreUntil("host", now.Add(-time.Second))

		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			_ = set.containsAt("host", now)
			done <- struct{}{}
		}()
		go func() {
			<-start
			set.StoreUntil("host", now.Add(time.Minute))
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done

		require.True(t, set.containsAt("host", now),
			"cleanup of the expired value must not delete a concurrent refresh")
	}
}
