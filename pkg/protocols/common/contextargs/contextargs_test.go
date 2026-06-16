package contextargs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUseNetworkPort(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		templatePort string
		excludePorts string
		wantInput    string
	}{
		{
			// No port in input → use template port (existing behaviour).
			name:         "no port in input uses template port",
			input:        "example.com",
			templatePort: "22",
			wantInput:    "example.com:22",
		},
		{
			// Input has a non-reserved port explicitly → must NOT be replaced.
			// This is the core of issue #7323: SSH on a non-standard port.
			name:         "explicit non-reserved port is preserved",
			input:        "example.com:2222",
			templatePort: "22",
			wantInput:    "example.com:2222",
		},
		{
			// Key regression: bare host:80 form — operator explicitly wants port 80
			// (e.g. SSH/other service listening on port 80). Must NOT be replaced.
			name:         "bare host:80 explicit port preserved (issue #7323)",
			input:        "example.com:80",
			templatePort: "22",
			wantInput:    "example.com:80",
		},
		{
			// http://host:80 — port 80 is scheme-implied, replacement is fine.
			name:         "scheme-implied port 80 is replaced",
			input:        "http://example.com:80",
			templatePort: "22",
			wantInput:    "example.com:22",
		},
		{
			// http://host (no port) — template port used.
			name:         "http scheme no port uses template port",
			input:        "http://example.com",
			templatePort: "8888",
			wantInput:    "example.com:8888",
		},
		{
			// Empty template port → no change.
			name:         "empty template port is noop",
			input:        "example.com:9999",
			templatePort: "",
			wantInput:    "example.com:9999",
		},
		{
			// Explicit port that equals template port → unchanged.
			name:         "explicit port matching template port unchanged",
			input:        "example.com:22",
			templatePort: "22",
			wantInput:    "example.com:22",
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
