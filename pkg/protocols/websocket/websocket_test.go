package websocket

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Keep duration assertions above the timer granularity of fast local sockets on Windows.
const durationObservationDelay = 10 * time.Millisecond

// resolveAddress mirrors the path resolution logic in executeRequestWithPayloads.
// it parses the template address and the input URL then applies the path rule.
func resolveAddress(templateAddress, inputURL string) (string, error) {
	parsedAddress, err := url.Parse(templateAddress)
	if err != nil {
		return "", err
	}
	parsed, err := urlutil.Parse(inputURL)
	if err != nil {
		return "", err
	}
	if parsedAddress.Path == "" || parsedAddress.Path == "/" {
		parsedAddress.Path = parsed.Path
	}
	return parsedAddress.String(), nil
}

func TestAddressResolution(t *testing.T) {
	tests := []struct {
		name            string
		templateAddress string
		inputURL        string
		expected        string
	}{
		// template already has a path so we keep it and don't double
		{
			name:            "same path in both - no doubling",
			templateAddress: "wss://jenkins.cloud/cli/ws",
			inputURL:        "https://jenkins.cloud/cli/ws",
			expected:        "wss://jenkins.cloud/cli/ws",
		},
		{
			name:            "different paths - template path preserved",
			templateAddress: "wss://example.com/ws/connect",
			inputURL:        "https://example.com/api/v1",
			expected:        "wss://example.com/ws/connect",
		},
		{
			name:            "deep template path preserved",
			templateAddress: "wss://example.com/a/b/c/d",
			inputURL:        "https://example.com/x/y",
			expected:        "wss://example.com/a/b/c/d",
		},
		{
			name:            "template path with trailing slash preserved",
			templateAddress: "wss://example.com/ws/",
			inputURL:        "https://example.com/other",
			expected:        "wss://example.com/ws/",
		},

		// when the template has no path we fall back to the input path
		{
			name:            "no template path - input path used",
			templateAddress: "wss://example.com",
			inputURL:        "https://example.com/api/ws",
			expected:        "wss://example.com/api/ws",
		},
		{
			name:            "root template path - input path used",
			templateAddress: "wss://example.com/",
			inputURL:        "https://example.com/chat/ws",
			expected:        "wss://example.com/chat/ws",
		},
		{
			name:            "no paths on either side",
			templateAddress: "wss://example.com",
			inputURL:        "https://example.com",
			expected:        "wss://example.com",
		},
		{
			name:            "root template, root input",
			templateAddress: "wss://example.com/",
			inputURL:        "https://example.com/",
			expected:        "wss://example.com/",
		},

		// ports should not affect path resolution
		{
			name:            "template with port and path",
			templateAddress: "wss://example.com:8443/ws",
			inputURL:        "https://example.com:8443/api",
			expected:        "wss://example.com:8443/ws",
		},
		{
			name:            "template with port, no path - input path used",
			templateAddress: "ws://example.com:9090",
			inputURL:        "http://example.com:9090/stream",
			expected:        "ws://example.com:9090/stream",
		},
		{
			name:            "ws scheme with port and deep input path",
			templateAddress: "ws://example.com:8080",
			inputURL:        "http://example.com:8080/api/v2/ws",
			expected:        "ws://example.com:8080/api/v2/ws",
		},

		// query strings should stay with their respective URLs
		{
			name:            "template with query string preserved",
			templateAddress: "wss://example.com/ws?token=abc",
			inputURL:        "https://example.com/other",
			expected:        "wss://example.com/ws?token=abc",
		},
		{
			name:            "input query string not leaked when template has path",
			templateAddress: "wss://example.com/ws",
			inputURL:        "https://example.com/api?key=secret",
			expected:        "wss://example.com/ws",
		},
		{
			name:            "no template path - input path used but not query",
			templateAddress: "wss://example.com",
			inputURL:        "https://example.com/stream?v=1",
			expected:        "wss://example.com/stream",
		},

		// both ws and wss schemes should behave the same way
		{
			name:            "ws scheme template path preserved",
			templateAddress: "ws://example.com/plain",
			inputURL:        "http://example.com/other",
			expected:        "ws://example.com/plain",
		},
		{
			name:            "wss scheme no path - input path used",
			templateAddress: "wss://secure.example.com",
			inputURL:        "https://secure.example.com/endpoint",
			expected:        "wss://secure.example.com/endpoint",
		},

		// same logic applies to IP-based targets
		{
			name:            "IPv4 template with path",
			templateAddress: "ws://192.168.1.1/ws",
			inputURL:        "http://192.168.1.1/api",
			expected:        "ws://192.168.1.1/ws",
		},
		{
			name:            "IPv4 template no path - input path used",
			templateAddress: "ws://192.168.1.1",
			inputURL:        "http://192.168.1.1/metrics/ws",
			expected:        "ws://192.168.1.1/metrics/ws",
		},
		{
			name:            "IPv4 with port, no path",
			templateAddress: "ws://10.0.0.1:3000",
			inputURL:        "http://10.0.0.1:3000/graphql/ws",
			expected:        "ws://10.0.0.1:3000/graphql/ws",
		},

		// patterns from actual templates and bug reports
		{
			name:            "jenkins websocket - the original bug report",
			templateAddress: "wss://jenkins-ci.corp.cloud/cli/ws",
			inputURL:        "https://jenkins-ci.corp.cloud/cli/ws",
			expected:        "wss://jenkins-ci.corp.cloud/cli/ws",
		},
		{
			name:            "grafana live websocket",
			templateAddress: "wss://grafana.local/api/live/ws",
			inputURL:        "https://grafana.local/api/live/ws",
			expected:        "wss://grafana.local/api/live/ws",
		},
		{
			name:            "generic host-only template with target path",
			templateAddress: "wss://target.example.com",
			inputURL:        "https://target.example.com/socket.io/ws",
			expected:        "wss://target.example.com/socket.io/ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveAddress(tt.templateAddress, tt.inputURL)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "ws scheme returns host",
			input: "ws://example.com/path",
			want:  "example.com",
		},
		{
			name:  "wss scheme returns host with port",
			input: "wss://example.com:8443/path",
			want:  "example.com:8443",
		},
		{
			name:  "ws with non-standard port",
			input: "ws://example.com:9090",
			want:  "example.com:9090",
		},
		{
			name:  "wss with standard port",
			input: "wss://example.com:443/ws",
			want:  "example.com:443",
		},
		{
			name:  "ws IPv4",
			input: "ws://192.168.1.1/ws",
			want:  "192.168.1.1",
		},
		{
			name:  "ws IPv4 with port",
			input: "ws://192.168.1.1:8080/ws",
			want:  "192.168.1.1:8080",
		},
		{
			name:    "http scheme rejected",
			input:   "http://example.com",
			wantErr: true,
		},
		{
			name:    "https scheme rejected",
			input:   "https://example.com",
			wantErr: true,
		},
		{
			name:    "ftp scheme rejected",
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			input:   "://broken",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAddress(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWebSocketDurationFields(t *testing.T) {
	connHandler := func(conn net.Conn) {
		for {
			msg, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			switch string(msg) {
			case "hello":
				time.Sleep(durationObservationDelay)
				_ = wsutil.WriteServerMessage(conn, op, []byte("world"))
			case "status":
				time.Sleep(durationObservationDelay)
				_ = wsutil.WriteServerMessage(conn, op, []byte("ready"))
			default:
				return
			}
		}
	}
	server := testutils.NewWebsocketServer("", connHandler, func(origin string) bool { return true })
	defer server.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	target := strings.ReplaceAll(server.URL, "http", "ws")
	request := &Request{
		ID:      "duration-ws",
		Address: target,
		Inputs: []*Input{
			{Data: "hello", Name: "first"},
			{Data: "status", Name: "second"},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-websocket-duration",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true
	require.NoError(t, request.Compile(executerOpts))
	require.Equal(t, "duration-ws", request.GetID())

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), target)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NotEmpty(t, gotEvent)
	requireWebsocketDurationField(t, gotEvent, "duration")
	requireWebsocketDurationField(t, gotEvent, "duration_1")
	requireWebsocketDurationField(t, gotEvent, "duration_2")
	require.Equal(t, gotEvent["duration_2"], gotEvent["duration"])
	extractor := &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
		DSL:  []string{"duration_2"},
	}
	require.NoError(t, extractor.CompileExtractors())
	require.NotEmpty(t, request.Extract(gotEvent, extractor))

	values := executerOpts.GetTemplateCtx(ctxArgs.MetaInput).GetAll()
	require.Equal(t, gotEvent["duration"], values["duration-ws_duration"])
	require.Equal(t, gotEvent["duration_1"], values["duration-ws_duration_1"])
	require.Equal(t, gotEvent["duration_2"], values["duration-ws_duration_2"])
}

func TestWebSocketNoInputDuration(t *testing.T) {
	server := newDelayedUpgradeWebsocketServer(durationObservationDelay)
	defer server.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	target := strings.ReplaceAll(server.URL, "http", "ws")
	request := &Request{
		ID:      "duration-ws-handshake",
		Address: target,
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-websocket-handshake-duration",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), target)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NotEmpty(t, gotEvent)
	requireWebsocketDurationField(t, gotEvent, "duration")
	require.NotContains(t, gotEvent, "duration_1")
}

func newDelayedUpgradeWebsocketServer(delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)

		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}

		go func() {
			defer func() {
				_ = conn.Close()
			}()
			time.Sleep(delay)
		}()
	}))
}

func requireWebsocketDurationField(t *testing.T, event output.InternalEvent, key string) {
	t.Helper()

	value, ok := event[key].(float64)
	require.Truef(t, ok, "expected %s to be a float64 duration", key)
	require.Greater(t, value, float64(0))
	require.Less(t, value, float64(60))
}
