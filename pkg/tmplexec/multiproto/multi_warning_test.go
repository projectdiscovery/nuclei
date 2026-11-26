package multiproto_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/multiproto"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

var (
	errRefused   = errors.New("connection refused")
	errHandshake = errors.New("could not do tls handshake")
)

// countingRequest is a request of the given protocol that sends nothing,
// counts its executions and returns err.
type countingRequest struct {
	protocols.Request

	protocolType templateTypes.ProtocolType
	err          error
	calls        *int
}

func (r countingRequest) Type() templateTypes.ProtocolType { return r.protocolType }

func (r countingRequest) GetID() string { return "" }

func (r countingRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	*r.calls++

	return r.err
}

// A failed request in a template with several request blocks warns once, like
// the generic executer does for a template with one, and the next block runs
// (#8238).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the logger is global
func TestFailedRequestWarns(t *testing.T) {
	tests := []struct {
		name         string
		protocolType templateTypes.ProtocolType
		err          error
		wantWarnings int
	}{
		{name: "skip", protocolType: templateTypes.HTTPProtocol, err: hosterrorscache.ErrUnresponsiveHost, wantWarnings: 0},
		{name: "failure", protocolType: templateTypes.HTTPProtocol, err: errRefused, wantWarnings: 1},
		// a tls handshake error is no exception in an ssl block
		{name: "ssl handshake failure", protocolType: templateTypes.SSLProtocol, err: errHandshake, wantWarnings: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logged bytes.Buffer

			gologger.DefaultLogger.SetWriter(&utils.CaptureWriter{Buffer: &logged})
			gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
			t.Cleanup(func() {
				// gologger's own defaults: it has no getter to save the previous ones
				gologger.DefaultLogger.SetWriter(writer.NewCLI())
				gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
			})

			var failedCalls, nextCalls int

			engine := multiproto.NewMultiProtocol(
				[]protocols.Request{
					countingRequest{protocolType: test.protocolType, err: test.err, calls: &failedCalls},
					countingRequest{protocolType: templateTypes.HTTPProtocol, calls: &nextCalls},
				},
				&protocols.ExecutorOptions{TemplateID: "t", Options: &types.Options{}},
				nil,
			)
			ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), "http://127.0.0.1"))

			require.NoError(t, engine.ExecuteWithResults(ctx))

			require.Equal(t, 1, failedCalls)
			require.Equal(t, 1, nextCalls)
			require.ErrorIs(t, ctx.GenerateErrorMessage(), test.err)

			warnings := bytes.Count(logged.Bytes(), []byte("Could not execute request"))

			require.Equal(t, test.wantWarnings, warnings, logged.String())
		})
	}
}

// cancelingRequest is a request that cancels the scan while it runs and returns
// the context error, as the HTTP protocol does.
type cancelingRequest struct {
	protocols.Request

	cancel context.CancelFunc
}

func (r cancelingRequest) Type() templateTypes.ProtocolType { return templateTypes.HTTPProtocol }

func (r cancelingRequest) GetID() string { return "" }

func (r cancelingRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	r.cancel()

	return context.Canceled
}

// A scan cancelled during a block that is not the last returns the context
// error without a warning: the engine warns about the returned error, so a
// warning here would print the cancellation twice.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the logger is global
func TestCanceledRequestReturnsContextError(t *testing.T) {
	var logged bytes.Buffer

	gologger.DefaultLogger.SetWriter(&utils.CaptureWriter{Buffer: &logged})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	t.Cleanup(func() {
		// gologger's own defaults: it has no getter to save the previous ones
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var nextCalls int

	engine := multiproto.NewMultiProtocol(
		[]protocols.Request{
			cancelingRequest{cancel: cancel},
			countingRequest{protocolType: templateTypes.HTTPProtocol, calls: &nextCalls},
		},
		&protocols.ExecutorOptions{TemplateID: "t", Options: &types.Options{}},
		nil,
	)
	ctx := scan.NewScanContext(goCtx, contextargs.NewWithInput(goCtx, "http://127.0.0.1"))

	require.ErrorIs(t, engine.ExecuteWithResults(ctx), context.Canceled)
	require.Zero(t, nextCalls)
	require.NotContains(t, logged.String(), "Could not execute request")
}
