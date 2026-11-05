package whois

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
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
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(redirector.URL, "http://"))
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.ExcludeTargets = []string{"127.0.0.1"}
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	// localhost passes the server check through ::1, while 127.0.0.1 is denied
	require.True(t, protocolstate.IsHostAllowed(options.ExecutionId, "localhost"))

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "whois-redirect"})
	request := &Request{ID: "whois-redirect", Query: "example.com", Server: "http://localhost:" + port + "/rdap/"}
	require.NoError(t, request.Compile(executerOpts))

	input := contextargs.NewWithInput(context.Background(), "example.com")
	_ = request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})
	require.Zero(t, hits.Load(), "whois redirect reached a denied address")
}
