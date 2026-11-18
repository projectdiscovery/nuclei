package rdapclientpool

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/rdap"
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
