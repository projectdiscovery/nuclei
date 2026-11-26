package generic_test

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
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/generic"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

var errRefused = errors.New("connection refused")

// failingRequest is a request that sends nothing and returns err.
type failingRequest struct {
	protocols.Request

	err error
}

func (r failingRequest) Type() templateTypes.ProtocolType { return templateTypes.HTTPProtocol }

func (r failingRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	return r.err
}

// A request skipped for an unresponsive address is logged on the scan, where
// the failure event reads it, and does not warn: the engine writes the same
// message for a target it skips, without a warning (#8196).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the logger is global
func TestUnresponsiveSkipIsLoggedWithoutWarning(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantWarning bool
	}{
		{name: "skip", err: hosterrorscache.ErrUnresponsiveHost, wantWarning: false},
		{name: "failure", err: errRefused, wantWarning: true},
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

			engine := generic.NewGenericEngine(
				[]protocols.Request{failingRequest{err: test.err}},
				&protocols.ExecutorOptions{TemplateID: "t", Options: &types.Options{}},
				nil,
			)
			ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), "http://127.0.0.1"))

			require.NoError(t, engine.ExecuteWithResults(ctx))

			require.ErrorIs(t, ctx.GenerateErrorMessage(), test.err)

			warned := bytes.Contains(logged.Bytes(), []byte("Could not execute request"))

			require.Equal(t, test.wantWarning, warned, logged.String())
		})
	}
}
