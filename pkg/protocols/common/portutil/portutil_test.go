package portutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolvePort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{input: "80", expected: "80"},
		{input: "443", expected: "443"},
		{input: "1", expected: "1"},
		{input: "65535", expected: "65535"},
		{input: "ftp", expected: "21"},
		{input: "ssh", expected: "22"},
		{input: "smtp", expected: "25"},
		{input: "http", expected: "80"},
		{input: "https", expected: "443"},
		{input: "mysql", expected: "3306"},
		{input: "redis", expected: "6379"},
		{input: "postgres", expected: "5432"},
		{input: "rdp", expected: "3389"},
		{input: "0", wantErr: true},
		{input: "65536", wantErr: true},
		{input: "nonsense", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ResolvePort(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}
}
