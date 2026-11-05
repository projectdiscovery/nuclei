package whois

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/stretchr/testify/require"
)

func TestWhoisServerRedirectObeysNetworkPolicy(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"domain","ldhName":"example.com"}`))
	}))
	t.Cleanup(internal.Close)
	// the redirector listens on ::1 so that it is reached while 127.0.0.1 is denied
	var redirects atomic.Int32
	redirector := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, internal.URL+r.URL.Path, http.StatusFound)
	}))
	listener, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	redirector.Listener = listener
	redirector.Start()
	t.Cleanup(redirector.Close)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"127.0.0.1"}
	testutils.Init(options)
	t.Cleanup(func() { protocolinit.Close(options.ExecutionId) })
	require.True(t, protocolstate.IsHostAllowed(options.ExecutionId, "::1"))

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "whois-redirect"})
	request := &Request{ID: "whois-redirect", Query: "example.com", Server: "http://[::1]:" + port + "/rdap/"}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), "example.com")
	_ = request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})
	require.NotZero(t, redirects.Load(), "the redirector was never reached")
	require.Zero(t, hits.Load(), "whois redirect reached a denied address")
}
