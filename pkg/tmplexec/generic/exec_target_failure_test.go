package generic_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/generic"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// succeedingNetworkRequest is a network request that sends nothing and succeeds.
type succeedingNetworkRequest struct {
	protocols.Request
}

func (succeedingNetworkRequest) Type() templateTypes.ProtocolType {
	return templateTypes.NetworkProtocol
}

func (succeedingNetworkRequest) ExecuteWithResults(
	*contextargs.Context, output.InternalEvent, output.InternalEvent, protocols.OutputEventCallback,
) error {
	return nil
}

// A network request that succeeds leaves the target's http failure in place.
// The failure belongs to the address the http requests went to, which the
// network request says nothing about, and clearing it would send later http
// templates to that address again (#8203).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults
func TestNonHTTPSuccessKeepsTargetFailure(t *testing.T) {
	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)

	protoType := templateTypes.HTTPProtocol.String()
	target := contextargs.NewWithInput(context.Background(), "https://127.0.0.1")
	cache.MarkFailedOrRemove(protoType, target, errRefused)
	require.True(t, cache.Check(protoType, target), "the refused address must be unresponsive")

	engine := generic.NewGenericEngine(
		[]protocols.Request{succeedingNetworkRequest{}},
		&protocols.ExecutorOptions{TemplateID: "t", Options: &types.Options{}, HostErrorsCache: cache},
		nil,
	)

	require.NoError(t, engine.ExecuteWithResults(scan.NewScanContext(context.Background(), target)))
	require.True(t, cache.Check(protoType, target), "the network request cleared the failure of the target's address")
}
