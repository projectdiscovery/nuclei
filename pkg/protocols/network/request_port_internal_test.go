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
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// serveReply answers every connection with reply and returns its port.
func serveReply(t *testing.T, reply string) string {
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

			_, _ = conn.Write([]byte(reply))
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

	templateReply = "TMPL"
	urlReply      = "URLP"
)

// runNetworkRequest transforms target as the executers do for the network
// protocol, runs a request with the given template port and excluded ports
// against it, and returns the data of every response.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func runNetworkRequest(t *testing.T, target, templatePort, excludePorts string) []string {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "network-port"})

	request := &Request{
		ID:           "network-port",
		Address:      []string{hostnameAddress},
		Port:         templatePort,
		ExcludePorts: excludePorts,
		ReadSize:     4,
		Matchers: []*matchers.Matcher{{
			Part:  dataPart,
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{templateReply, urlReply},
		}},
	}
	require.NoError(t, request.Compile(executerOpts))

	transformed := input.NewHelper().Transform(target, templateTypes.NetworkProtocol)

	var responses []string

	ctx := contextargs.NewWithInput(context.Background(), transformed)
	err := request.ExecuteWithResults(ctx, output.InternalEvent{}, output.InternalEvent{},
		func(event *output.InternalWrappedEvent) {
			if event != nil && event.HasOperatorResult() {
				responses = append(responses, types.ToString(event.InternalEvent[dataPart]))
			}
		})
	require.NoError(t, err)

	return responses
}

// TestTemplatePortWithSchemeTarget runs a template port against the targets
// the executers hand over, which they transform for the network protocol first.
//
//nolint:exhaustruct,exhaustruct_v5,funlen,paralleltest // cases leave fields empty; the test options are global
func TestTemplatePortWithSchemeTarget(t *testing.T) {
	// The template port answers templateReply and the port a target names
	// answers urlReply, so the reply tells which one was dialed.
	templatePort := serveReply(t, templateReply)
	urlPort := serveReply(t, urlReply)

	const (
		reservedHTTP  = "http://127.0.0.1:8080"
		reservedHTTPS = "https://127.0.0.1:8443"
	)

	tmpl := []string{templateReply}
	url := []string{urlReply}

	tests := []struct {
		name         string
		target       string
		templatePort string
		excludePorts string
		want         []string
	}{
		{name: "bare host", target: "127.0.0.1", templatePort: templatePort, want: tmpl},
		{name: "http without a port", target: "http://127.0.0.1", templatePort: templatePort, want: tmpl},
		{name: "https without a port", target: "https://127.0.0.1", templatePort: templatePort, want: tmpl},
		{name: "https with a path and no port", target: "https://127.0.0.1/path", templatePort: templatePort, want: tmpl},
		// A reserved port named in a URL is replaced, as the port field says.
		{name: "http with reserved port 8080", target: reservedHTTP, templatePort: templatePort, want: tmpl},
		{name: "https with reserved port 8443", target: reservedHTTPS, templatePort: templatePort, want: tmpl},
		{name: "http with reserved port and a path", target: reservedHTTP + "/path", templatePort: templatePort, want: tmpl},
		// With several template ports, each one replaces the reserved port.
		{
			name:         "http with reserved port and two template ports",
			target:       reservedHTTP,
			templatePort: templatePort + "," + urlPort,
			want:         []string{templateReply, urlReply},
		},
		// A port that is not reserved, or typed without a scheme, is kept.
		{name: "http with a free port", target: "http://127.0.0.1:" + urlPort, templatePort: templatePort, want: url},
		{name: "bare host with a port", target: "127.0.0.1:" + urlPort, templatePort: templatePort, want: url},
		// The template without a port dials the port the target names.
		{name: "no template port with http and a port", target: "http://127.0.0.1:" + urlPort, want: url},
		{name: "no template port with a bare port", target: "127.0.0.1:" + urlPort, want: url},
		// exclude-ports replaces the reserved list, for a URL target only.
		{
			name:         "http with an excluded port",
			target:       "http://127.0.0.1:" + urlPort,
			templatePort: templatePort,
			excludePorts: urlPort,
			want:         tmpl,
		},
		{
			name:         "bare host with an excluded port",
			target:       "127.0.0.1:" + urlPort,
			templatePort: templatePort,
			excludePorts: urlPort,
			want:         url,
		},
		{
			name:         "http with a port that exclude-ports leaves out",
			target:       "http://127.0.0.1:" + urlPort,
			templatePort: templatePort,
			excludePorts: "8080",
			want:         url,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses := runNetworkRequest(t, tt.target, tt.templatePort, tt.excludePorts)
			require.ElementsMatch(t, tt.want, responses)
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
