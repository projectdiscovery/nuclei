package rdapclientpool

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openrdap/rdap"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func newRdapServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"domain","ldhName":"example.com"}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func rdapOptions(t *testing.T, executionID string, excludeTargets []string) *types.Options {
	t.Helper()
	options := types.DefaultOptions()
	options.ExecutionId = executionID
	options.ExcludeTargets = excludeTargets
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })
	require.NoError(t, Init(options))
	t.Cleanup(func() { Close(options.ExecutionId) })
	return options
}

func domainRequest(t *testing.T, server string) *rdap.Request {
	t.Helper()
	serverURL, err := url.Parse(server)
	require.NoError(t, err)
	request := rdap.NewAutoRequest("example.com")
	request.Server = serverURL
	return request
}

// Each execution gets a client that dials with its own network policy.
func TestClientObeysExecutionNetworkPolicy(t *testing.T) {
	var hits atomic.Int32
	server := newRdapServer(t, &hits)

	open := rdapOptions(t, t.Name()+"-open", nil)
	restricted := rdapOptions(t, t.Name()+"-restricted", []string{"127.0.0.1"})

	openClient, err := Get(open, nil)
	require.NoError(t, err)
	_, err = openClient.Do(domainRequest(t, server.URL))
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	restrictedClient, err := Get(restricted, nil)
	require.NoError(t, err)
	_, err = restrictedClient.Do(domainRequest(t, server.URL))
	require.Error(t, err)
	require.Equal(t, int32(1), hits.Load(), "rdap request reached a denied address")
}

func TestClientDoConcurrent(t *testing.T) {
	var hits atomic.Int32
	server := newRdapServer(t, &hits)
	options := rdapOptions(t, t.Name(), nil)
	client, err := Get(options, nil)
	require.NoError(t, err)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	const requests = 32
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			request := rdap.NewAutoRequest("example.com")
			request.Server = serverURL
			_, err := client.Do(request)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(requests), hits.Load())
}
