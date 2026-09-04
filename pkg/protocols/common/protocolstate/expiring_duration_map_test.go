package protocolstate

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpiringDurationMapKeepsMinimumAndExpires(t *testing.T) {
	values := NewExpiringDurationMap(time.Millisecond)
	values.StoreMin("host", 20*time.Millisecond, 30*time.Millisecond)
	values.StoreMin("host", 50*time.Millisecond, 30*time.Millisecond)
	value, ok := values.Load("host")
	require.True(t, ok)
	require.Equal(t, 20*time.Millisecond, value)

	values.StoreMin("host", 10*time.Millisecond, 5*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	_, ok = values.Load("host")
	require.False(t, ok)
}

func TestExpiringDurationMapConcurrentMinimum(t *testing.T) {
	values := NewExpiringDurationMap(time.Minute)
	var wg sync.WaitGroup
	for value := 100; value > 0; value-- {
		wg.Add(1)
		go func() {
			defer wg.Done()
			values.StoreMin("host", time.Duration(value)*time.Millisecond, time.Minute)
		}()
	}
	wg.Wait()

	value, ok := values.Load("host")
	require.True(t, ok)
	require.Equal(t, time.Millisecond, value)
}
