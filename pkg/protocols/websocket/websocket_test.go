package websocket

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	urlutil "github.com/projectdiscovery/utils/url"
)

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
