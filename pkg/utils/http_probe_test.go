package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetermineSchemeOrder(t *testing.T) {
	type testCase struct {
		input    string
		expected []string
	}

	tests := []testCase{
		// No port or uncommon ports should return https first
		{"example.com", []string{"https", "http"}},
		{"example.com:443", []string{"https", "http"}},
		{"127.0.0.1", []string{"https", "http"}},
		{"[fe80::1]:443", []string{"https", "http"}},
		// Common HTTP ports should return http first
		{"example.com:80", []string{"http", "https"}},
		{"example.com:8080", []string{"http", "https"}},
		{"127.0.0.1:80", []string{"http", "https"}},
		{"127.0.0.1:8080", []string{"http", "https"}},
		{"fe80::1", []string{"https", "http"}},
		{"[fe80::1]:80", []string{"http", "https"}},
		{"[fe80::1]:8080", []string{"http", "https"}},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			actual := determineSchemeOrder(tc.input)
			require.Equal(t, tc.expected, actual)
		})
	}
}
