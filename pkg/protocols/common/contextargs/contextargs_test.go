package contextargs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUseNetworkPort(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		templatePort string
		templateExcl string
		expectedHost string
	}{
		{
			name:         "default-reserved-port-is-rewritten",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "",
			expectedHost: "example.com:1234",
		},
		{
			name:         "non-reserved-target-port-is-preserved",
			target:       "example.com:22",
			templatePort: "80",
			templateExcl: "",
			expectedHost: "example.com:22",
		},
		{
			name:         "template-exclusions-replace-default-reserved-ports",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "0",
			expectedHost: "example.com:80",
		},
		{
			name:         "template-excluded-port-is-applied",
			target:       "example.com:5353",
			templatePort: "1234",
			templateExcl: "5353",
			expectedHost: "example.com:1234",
		},
		{
			name:         "template-excluded-port-list-is-applied",
			target:       "example.com:443",
			templatePort: "1234",
			templateExcl: "80,443",
			expectedHost: "example.com:1234",
		},
		{
			name:         "template-excluded-port-with-whitespace-is-applied",
			target:       "example.com:443",
			templatePort: "1234",
			templateExcl: "443 ",
			expectedHost: "example.com:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewWithInput(context.Background(), tt.target)
			err := ctx.UseNetworkPort(tt.templatePort, tt.templateExcl)

			require.NoError(t, err, "unexpected error")
			require.Equal(t, tt.expectedHost, ctx.MetaInput.Input)
		})
	}
}
