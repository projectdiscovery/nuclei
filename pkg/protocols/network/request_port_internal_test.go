package network

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// servePong answers every connection with "PONG" and returns its port.
func servePong(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig

	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			_, _ = conn.Write([]byte("PONG"))
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	return port
}

const (
	hostnameAddress = "{{Hostname}}"
	dataPart        = "data"
)

// TestTemplatePortWithSchemeTarget runs a template port against the targets
// the executers hand over, which they transform for the network protocol first.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestTemplatePortWithSchemeTarget(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "http://127.0.0.1", "https://127.0.0.1", "https://127.0.0.1/path"} {
		t.Run(target, func(t *testing.T) {
			port := servePong(t)

			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-port"})

			request := &Request{
				ID:       "network-port",
				Address:  []string{hostnameAddress},
				Port:     port,
				ReadSize: 4,
				Matchers: []*matchers.Matcher{{
					Part:  dataPart,
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"PONG"},
				}},
			}
			require.NoError(t, request.Compile(executerOpts))

			transformed := input.NewHelper().Transform(target, templateTypes.NetworkProtocol)

			var matched bool

			ctx := contextargs.NewWithInput(context.Background(), transformed)
			err := request.ExecuteWithResults(ctx, output.InternalEvent{}, output.InternalEvent{},
				func(event *output.InternalWrappedEvent) {
					matched = matched || (event != nil && event.HasOperatorResult())
				})
			require.NoError(t, err)
			require.True(t, matched, "the template port is dialed for %s", target)
		})
	}
}

func TestGetAddress(t *testing.T) {
	t.Parallel()

	for target, want := range map[string]string{
		"127.0.0.1:81":            "127.0.0.1:81",
		"http://127.0.0.1:8080":   "127.0.0.1:8080",
		"https://127.0.0.1:8443":  "127.0.0.1:8443",
		"https://127.0.0.1":       "127.0.0.1:443",
		"https://127.0.0.1/path":  "127.0.0.1:443",
		"https://[::1]":           "[::1]:443",
		"https://example.com/a:b": "example.com:443",
	} {
		got, err := getAddress(target)
		require.NoError(t, err, target)
		require.Equal(t, want, got, target)
	}
}
