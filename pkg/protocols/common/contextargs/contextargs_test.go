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
		cliReserved  []string
		expectedHost string
	}{
		{
			name:         "default-reserved-port-is-rewritten",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "non-reserved-target-port-is-preserved",
			target:       "example.com:22",
			templatePort: "80",
			templateExcl: "",
			cliReserved:  nil,
			expectedHost: "example.com:22",
		},
		{
			name:         "template-exclusions-replace-default-reserved-ports",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "0",
			cliReserved:  nil,
			expectedHost: "example.com:80",
		},
		{
			name:         "template-excluded-port-is-applied",
			target:       "example.com:5353",
			templatePort: "1234",
			templateExcl: "5353",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "template-excluded-port-list-is-applied",
			target:       "example.com:443",
			templatePort: "1234",
			templateExcl: "80,443",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "template-excluded-port-with-whitespace-is-applied",
			target:       "example.com:443",
			templatePort: "1234",
			templateExcl: "443 ",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "cli-exclusions-take-precedence-over-template-exclusions",
			target:       "example.com:80",
			templatePort: "2345",
			templateExcl: "0",
			cliReserved:  []string{"80"},
			expectedHost: "example.com:2345",
		},
		{
			name:         "cli-exclusions-replace-default-reserved-ports",
			target:       "example.com:80",
			templatePort: "2345",
			templateExcl: "",
			cliReserved:  []string{"0"},
			expectedHost: "example.com:80",
		},
		{
			name:         "cli-excluded-port-is-applied",
			target:       "example.com:5353",
			templatePort: "2345",
			templateExcl: "",
			cliReserved:  []string{"5353"},
			expectedHost: "example.com:2345",
		},
		{
			name:         "cli-excluded-port-with-whitespace-is-applied",
			target:       "example.com:443",
			templatePort: "2345",
			templateExcl: "",
			cliReserved:  []string{"80", " 443"},
			expectedHost: "example.com:2345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewWithInput(context.Background(), tt.target)
			err := ctx.UseNetworkPort(tt.templatePort, tt.templateExcl, tt.cliReserved)

			require.NoError(t, err, "unexpected error")
			require.Equal(t, tt.expectedHost, ctx.MetaInput.Input)
		})
	}
}
