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
			name:         "default-reserved-ports-work",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "default-target-works",
			target:       "example.com:22",
			templatePort: "80",
			templateExcl: "",
			cliReserved:  nil,
			expectedHost: "example.com:22",
		},
		{
			name:         "template-overwrites-defaults-no-exclusions",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "0",
			cliReserved:  nil,
			expectedHost: "example.com:80",
		},
		{
			name:         "template-overwrites-defaults-some-exclusions",
			target:       "example.com:5353",
			templatePort: "1234",
			templateExcl: "5353",
			cliReserved:  nil,
			expectedHost: "example.com:1234",
		},
		{
			name:         "cli-overwrites-template",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "0",
			cliReserved:  []string{"80"},
			expectedHost: "example.com:1234",
		},
		{
			name:         "cli-overwrites-default-no-exclusions",
			target:       "example.com:80",
			templatePort: "1234",
			templateExcl: "",
			cliReserved:  []string{"0"},
			expectedHost: "example.com:80",
		},
		{
			name:         "cli-overwrites-default-some-exclusions",
			target:       "example.com:5353",
			templatePort: "1234",
			templateExcl: "",
			cliReserved:  []string{"5353"},
			expectedHost: "example.com:1234",
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
