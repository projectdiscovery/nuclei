package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetJsonFieldsFromURL_HostPortExtraction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		expectedHost string
		expectedPort string
	}{
		{
			name:         "URL with scheme and port",
			input:        "http://example.com:8080/path",
			expectedHost: "example.com",
			expectedPort: "8080",
		},
		{
			name:         "URL with scheme no port",
			input:        "https://example.com/path",
			expectedHost: "example.com",
			expectedPort: "443",
		},
		{
			name:         "host:port without scheme",
			input:        "example.com:8080",
			expectedHost: "example.com",
			expectedPort: "8080",
		},
		{
			name:         "host:port with standard HTTPS port",
			input:        "example.com:443",
			expectedHost: "example.com",
			expectedPort: "443",
		},
		{
			name:         "IPv4 with port",
			input:        "192.168.1.1:8080",
			expectedHost: "192.168.1.1",
			expectedPort: "8080",
		},
		{
			name:         "IPv6 with port",
			input:        "[2001:db8::1]:8080",
			expectedHost: "2001:db8::1",
			expectedPort: "8080",
		},
		{
			name:         "localhost with port",
			input:        "localhost:3000",
			expectedHost: "localhost",
			expectedPort: "3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fields := GetJsonFieldsFromURL(tt.input)

			assert.Equal(t, tt.expectedHost, fields.Host)
			assert.Equal(t, tt.expectedPort, fields.Port)
		})
	}
}

func TestExtractHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		host         string
		port         string
		expectedHost string
		expectedPort string
	}{
		{
			name:         "host without port",
			host:         "example.com",
			port:         "",
			expectedHost: "example.com",
			expectedPort: "",
		},
		{
			name:         "host with port",
			host:         "example.com:8080",
			port:         "",
			expectedHost: "example.com",
			expectedPort: "8080",
		},
		{
			name:         "port already set",
			host:         "example.com:8080",
			port:         "443",
			expectedHost: "example.com",
			expectedPort: "443",
		},
		{
			name:         "IPv6 with port",
			host:         "[::1]:8080",
			port:         "",
			expectedHost: "::1",
			expectedPort: "8080",
		},
		{
			name:         "IPv6 without port",
			host:         "[::1]",
			port:         "",
			expectedHost: "::1",
			expectedPort: "",
		},
		{
			name:         "IPv4 with port",
			host:         "192.168.1.1:8080",
			port:         "",
			expectedHost: "192.168.1.1",
			expectedPort: "8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, port := extractHostPort(tt.host, tt.port)

			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}
