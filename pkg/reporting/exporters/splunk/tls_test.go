package splunk

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExporterVerifiesTLS(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)

	opts := types.DefaultOptions()
	opts.SetExecutionID("splunk-tls-verify")
	require.NoError(t, protocolstate.Init(opts))
	defer protocolstate.Close(opts.ExecutionId)

	newExporter := func(skipVerify bool) *Exporter {
		e, err := New(&Options{Host: host, Port: p, SSL: true, SSLVerification: skipVerify, Token: "secret", IndexName: "nuclei", ExecutionId: opts.ExecutionId})
		require.NoError(t, err)
		return e
	}

	err = newExporter(false).Export(&output.ResultEvent{})
	require.ErrorContains(t, err, "certificate")
	require.Zero(t, got.Load(), "the token went to an untrusted server")

	require.NoError(t, newExporter(true).Export(&output.ResultEvent{}))
	require.EqualValues(t, 1, got.Load())
}
