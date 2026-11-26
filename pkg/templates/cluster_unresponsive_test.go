package templates //nolint:testpackage // it builds the unexported ClusterExecuter

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

var errRefused = errors.New("connection refused")

// failingRequest is a request that sends nothing and returns err.
type failingRequest struct {
	protocols.Request

	err error
}

func (r failingRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	return r.err
}

// A cluster whose request is skipped for an unresponsive address reports the
// skip in a failure event for each member, as the engine does for a target it
// skips, and returns no error, which the engine would warn about (#8196).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults
func TestClusterReportsUnresponsiveSkip(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "skip", err: hosterrorscache.ErrUnresponsiveHost, wantErr: nil},
		{name: "failure", err: errRefused, wantErr: errRefused},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := testutils.NewMockOutputWriter(false)

			var failures []string

			mock.WriteCallback = func(event *output.ResultEvent) {
				failures = append(failures, event.TemplateID+": "+event.Error)
			}
			cluster := &ClusterExecuter{
				requests:     failingRequest{err: test.err},
				templateType: templateTypes.HTTPProtocol,
				operators:    []*clusteredOperator{{templateID: "a"}, {templateID: "b"}},
				options:      &protocols.ExecutorOptions{Options: &types.Options{MatcherStatus: true}, Output: mock},
			}
			input := contextargs.NewWithInput(context.Background(), "http://127.0.0.1")

			_, err := cluster.Execute(scan.NewScanContext(context.Background(), input))

			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, []string{"a: " + test.err.Error(), "b: " + test.err.Error()}, failures)

			_, err = cluster.ExecuteWithResults(scan.NewScanContext(context.Background(), input))

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// succeedingNetworkRequest is a network request that sends nothing and succeeds.
type succeedingNetworkRequest struct {
	protocols.Request
}

func (succeedingNetworkRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	return nil
}

// A cluster of network requests that succeeds leaves the target's http failure
// in place, as a template run on its own does (#8203).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults
func TestNonHTTPClusterKeepsTargetFailure(t *testing.T) {
	tests := []struct {
		name string
		run  func(*ClusterExecuter, *scan.ScanContext) error
	}{
		{name: "Execute", run: func(c *ClusterExecuter, ctx *scan.ScanContext) error {
			_, err := c.Execute(ctx)

			return err
		}},
		{name: "ExecuteWithResults", run: func(c *ClusterExecuter, ctx *scan.ScanContext) error {
			_, err := c.ExecuteWithResults(ctx)

			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
			t.Cleanup(cache.Close)

			protoType := templateTypes.HTTPProtocol.String()
			target := contextargs.NewWithInput(context.Background(), "https://127.0.0.1")
			cache.MarkFailedOrRemove(protoType, target, errRefused)
			require.True(t, cache.Check(protoType, target), "the refused address must be unresponsive")

			cluster := &ClusterExecuter{
				requests:     succeedingNetworkRequest{},
				templateType: templateTypes.NetworkProtocol,
				operators:    []*clusteredOperator{{templateID: "a"}, {templateID: "b"}},
				options: &protocols.ExecutorOptions{
					Options: &types.Options{}, Output: testutils.NewMockOutputWriter(false), HostErrorsCache: cache,
				},
			}

			require.NoError(t, test.run(cluster, scan.NewScanContext(context.Background(), target)))
			require.True(t, cache.Check(protoType, target), "the cluster cleared the failure of the target's address")
		})
	}
}
