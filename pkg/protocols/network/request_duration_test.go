package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/utils/reader"
)

// Keep duration assertions above the timer granularity of fast local sockets on Windows.
const durationObservationDelay = 10 * time.Millisecond

func TestNetworkStepDurations(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	errState := &capturedError{}
	server := testutils.NewTCPServer(nil, 0, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()

		data, err := reader.ConnReadNWithTimeout(conn, 5, 5*time.Second)
		if err != nil {
			errState.Set(err)
			return
		}
		if string(data) != "FIRST" {
			errState.Set(fmt.Errorf("invalid first data received: %s", string(data)))
			return
		}
		time.Sleep(durationObservationDelay)
		_, _ = conn.Write([]byte("PING"))

		data, err = reader.ConnReadNWithTimeout(conn, 6, 5*time.Second)
		if err != nil {
			errState.Set(err)
			return
		}
		if string(data) != "SECOND" {
			errState.Set(fmt.Errorf("invalid second data received: %s", string(data)))
			return
		}
		time.Sleep(durationObservationDelay)
		_, _ = conn.Write([]byte("PONG"))
		_, _ = conn.Write([]byte("NUCLEI"))
	})
	defer server.Close()

	request := &Request{
		ID:       "duration-network",
		Address:  []string{"{{Hostname}}"},
		ReadSize: 6,
		Inputs: []*Input{
			{Data: "FIRST", Read: 4, Name: "first"},
			{Data: "SECOND", Read: 4, Name: "second"},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-network-duration",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), server.URL)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NoError(t, errState.Err())

	requireDurationField(t, gotEvent, "duration")
	requireDurationField(t, gotEvent, "duration_1")
	requireDurationField(t, gotEvent, "duration_2")
	require.NotContains(t, gotEvent, "duration_3")
	require.Equal(t, gotEvent["duration_2"], gotEvent["duration"])

	values := executerOpts.GetTemplateCtx(ctxArgs.MetaInput).GetAll()
	require.Equal(t, gotEvent["duration"], values["duration-network_duration"])
	require.Equal(t, gotEvent["duration_1"], values["duration-network_duration_1"])
	require.Equal(t, gotEvent["duration_2"], values["duration-network_duration_2"])
	require.NotContains(t, values, "duration-network_duration_3")
}

func requireDurationField(t *testing.T, event output.InternalEvent, key string) {
	t.Helper()

	value, ok := event[key].(float64)
	require.Truef(t, ok, "expected %s to be a float64 duration", key)
	require.Greater(t, value, float64(0))
	require.Less(t, value, float64(60))
}

type capturedError struct {
	mu  sync.Mutex
	err error
}

func (c *capturedError) Set(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *capturedError) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
