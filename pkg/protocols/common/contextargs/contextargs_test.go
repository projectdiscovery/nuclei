package contextargs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUseNetworkPort is the behavior matrix for UseNetworkPort.
//
// The contract (see issue #7323):
//   - empty template port            -> no-op, input untouched
//   - input with no port             -> input gets the template port
//   - bare "host:port" (no scheme)   -> operator-chosen port, always preserved
//   - "scheme://host:port"           -> port is scheme-implied; a reserved
//     (or excluded) port is replaced by the template port, otherwise preserved
func TestUseNetworkPort(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		templatePort string
		excludePorts string
		wantInput    string
	}{
		// --- empty template port: always a no-op ---
		{
			name:         "empty template port leaves bare host:port untouched",
			input:        "example.com:9999",
			templatePort: "",
			wantInput:    "example.com:9999",
		},
		{
			name:         "empty template port leaves no-port input untouched",
			input:        "example.com",
			templatePort: "",
			wantInput:    "example.com",
		},

		// --- no port in input: template port is applied ---
		{
			name:         "bare host without port uses template port",
			input:        "example.com",
			templatePort: "22",
			wantInput:    "example.com:22",
		},
		{
			name:         "http scheme without port uses template port",
			input:        "http://example.com",
			templatePort: "8888",
			wantInput:    "example.com:8888",
		},
		{
			name:         "https scheme without port uses template port",
			input:        "https://example.com",
			templatePort: "9090",
			wantInput:    "example.com:9090",
		},
		{
			name:         "http scheme with path and no port uses template port",
			input:        "http://example.com/some/path",
			templatePort: "8888",
			wantInput:    "example.com:8888",
		},

		// --- bare host:port (no scheme): operator intent, never replaced ---
		{
			// core of issue #7323: SSH (or anything) on port 80.
			name:         "bare host with reserved port 80 is preserved",
			input:        "example.com:80",
			templatePort: "22",
			wantInput:    "example.com:80",
		},
		{
			name:         "bare host with reserved port 443 is preserved",
			input:        "example.com:443",
			templatePort: "22",
			wantInput:    "example.com:443",
		},
		{
			name:         "bare host with reserved port 8080 is preserved",
			input:        "example.com:8080",
			templatePort: "22",
			wantInput:    "example.com:8080",
		},
		{
			name:         "bare host with reserved port 53 is preserved",
			input:        "example.com:53",
			templatePort: "22",
			wantInput:    "example.com:53",
		},
		{
			name:         "bare host with non-reserved port is preserved",
			input:        "example.com:2222",
			templatePort: "22",
			wantInput:    "example.com:2222",
		},
		{
			name:         "bare host with port equal to template port is preserved",
			input:        "example.com:22",
			templatePort: "22",
			wantInput:    "example.com:22",
		},

		// --- scheme + reserved port: scheme-implied, replaced ---
		{
			name:         "http scheme with reserved port 80 is replaced",
			input:        "http://example.com:80",
			templatePort: "22",
			wantInput:    "example.com:22",
		},
		{
			name:         "https scheme with reserved port 443 is replaced",
			input:        "https://example.com:443",
			templatePort: "22",
			wantInput:    "example.com:22",
		},
		{
			name:         "http scheme with reserved port 8080 is replaced",
			input:        "http://example.com:8080",
			templatePort: "22",
			wantInput:    "example.com:22",
		},

		// --- scheme + non-reserved port: preserved ---
		// Note: when the port is preserved the input is left exactly as-is (the
		// scheme is kept). Only the replace path rewrites to bare "host:port".
		// getAddress() strips the scheme before dialing, so both forms dial the
		// same address.
		{
			name:         "http scheme with non-reserved port is preserved verbatim",
			input:        "http://example.com:9999",
			templatePort: "22",
			wantInput:    "http://example.com:9999",
		},

		// --- excludePorts: replaces the default reserved set ---
		{
			name:         "scheme port in excludePorts is replaced",
			input:        "http://example.com:9090",
			templatePort: "22",
			excludePorts: "9090",
			wantInput:    "example.com:22",
		},
		{
			name:         "scheme port not in excludePorts is preserved verbatim",
			input:        "http://example.com:9091",
			templatePort: "22",
			excludePorts: "9090",
			wantInput:    "http://example.com:9091",
		},
		{
			// excludePorts replaces the reserved list, so 80 is no longer ignored
			// and the scheme-prefixed input is preserved verbatim.
			name:         "scheme reserved port not in custom excludePorts is preserved verbatim",
			input:        "http://example.com:80",
			templatePort: "22",
			excludePorts: "9090",
			wantInput:    "http://example.com:80",
		},
		{
			name:         "scheme multiple excludePorts replaces matching",
			input:        "http://example.com:8443",
			templatePort: "22",
			excludePorts: "9090,8443",
			wantInput:    "example.com:22",
		},
		{
			// bare host:port is preserved even when the port is in excludePorts.
			name:         "bare host port in excludePorts is still preserved",
			input:        "example.com:9090",
			templatePort: "22",
			excludePorts: "9090",
			wantInput:    "example.com:9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewWithInput(context.Background(), tt.input)
			err := ctx.UseNetworkPort(tt.templatePort, tt.excludePorts)
			require.NoError(t, err)
			require.Equal(t, tt.wantInput, ctx.MetaInput.Input)
		})
	}
}

// TestUseNetworkPortIPv6 keeps IPv6 handling honest: bracketed literals must be
// preserved and the reserved/scheme rules apply the same way as for hostnames.
func TestUseNetworkPortIPv6(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		templatePort string
		wantInput    string
	}{
		{
			name:         "bare IPv6 with reserved port is preserved",
			input:        "[::1]:80",
			templatePort: "22",
			wantInput:    "[::1]:80",
		},
		{
			name:         "bare IPv6 with non-reserved port is preserved",
			input:        "[2001:db8::1]:2222",
			templatePort: "22",
			wantInput:    "[2001:db8::1]:2222",
		},
		{
			name:         "scheme IPv6 with reserved port is replaced",
			input:        "http://[::1]:80",
			templatePort: "22",
			wantInput:    "[::1]:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewWithInput(context.Background(), tt.input)
			err := ctx.UseNetworkPort(tt.templatePort, "")
			require.NoError(t, err)
			require.Equal(t, tt.wantInput, ctx.MetaInput.Input)
		})
	}
}

func TestTemplateVariableOwnershipClearsOnDataWrites(t *testing.T) {
	ctx := New(context.Background())

	ctx.MergeTemplateVariables(map[string]interface{}{
		"token": "{{extracted_token}}",
	})
	require.Equal(t, map[string]interface{}{"token": "{{extracted_token}}"}, ctx.GetTemplateVariables())

	ctx.Set("token", "{{runtime_token}}")
	require.Empty(t, ctx.GetTemplateVariables())

	ctx.MergeTemplateVariables(map[string]interface{}{
		"token": "{{extracted_token}}",
	})
	ctx.Merge(map[string]interface{}{
		"token": "{{runtime_token}}",
	})
	require.Empty(t, ctx.GetTemplateVariables())
	require.Equal(t, map[string]interface{}{"token": "{{runtime_token}}"}, ctx.GetAll())
}

func TestTemplateVariableOwnershipIsCloned(t *testing.T) {
	ctx := New(context.Background())
	ctx.MergeTemplateVariables(map[string]interface{}{
		"token": "{{extracted_token}}",
	})

	cloned := ctx.Clone()
	require.Equal(t, map[string]interface{}{"token": "{{extracted_token}}"}, cloned.GetTemplateVariables())

	cloned.Set("token", "{{runtime_token}}")
	require.Empty(t, cloned.GetTemplateVariables())
	require.Equal(t, map[string]interface{}{"token": "{{extracted_token}}"}, ctx.GetTemplateVariables())
}

// TestUseNetworkPortServiceNameExclude verifies excludePorts accepts service
// names (resolved via portutil), e.g. "http" -> "80".
func TestUseNetworkPortServiceNameExclude(t *testing.T) {
	ctx := NewWithInput(context.Background(), "http://example.com:80")
	err := ctx.UseNetworkPort("22", "http")
	require.NoError(t, err)
	require.Equal(t, "example.com:22", ctx.MetaInput.Input)
}

// TestUseNetworkPortIdempotent ensures repeated application is stable and does
// not keep mutating the input.
func TestUseNetworkPortIdempotent(t *testing.T) {
	ctx := NewWithInput(context.Background(), "example.com")
	for i := 0; i < 3; i++ {
		require.NoError(t, ctx.UseNetworkPort("22", ""))
		require.Equal(t, "example.com:22", ctx.MetaInput.Input)
	}

	// A preserved bare explicit port must stay stable too.
	ctx = NewWithInput(context.Background(), "example.com:80")
	for i := 0; i < 3; i++ {
		require.NoError(t, ctx.UseNetworkPort("22", ""))
		require.Equal(t, "example.com:80", ctx.MetaInput.Input)
	}
}
