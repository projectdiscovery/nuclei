package protocolstate

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/networkpolicy"
	"github.com/stretchr/testify/require"
)

func TestIsHostAllowedRacesExcludeUpdate(t *testing.T) {
	np, err := networkpolicy.New(networkpolicy.Options{DenyList: []string{"127.0.0.0/8"}})
	require.NoError(t, err)

	const executionID = "exclude-race"
	entry := &Dialers{NetworkPolicy: np, ExcludeTargets: []string{"192.0.2.1"}}
	err = dialers.Set(executionID, entry)
	require.NoError(t, err)
	t.Cleanup(func() { dialers.Delete(executionID) })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		lists := [][]string{{"192.0.2.1"}, {"192.0.2.2", "192.0.2.3"}}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			entry.Lock()
			entry.ExcludeTargets = lists[i%2]
			entry.Unlock()
			i++
		}
	}()

	for i := 0; i < 2000; i++ {
		_ = IsHostAllowed(executionID, "http://192.0.2.1")
	}
	close(stop)
	wg.Wait()
}
