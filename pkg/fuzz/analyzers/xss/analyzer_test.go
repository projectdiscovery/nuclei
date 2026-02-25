package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetermineContext(t *testing.T) {
	payload := "pwned_payload"

	tests := []struct {
		name     string
		htmlBody string
		expected string
	}{
		{
			name:     "HTML Text Context",
			htmlBody: "<html><body>Hello pwned_payload world</body></html>",
			expected: "HTML Text",
		},
		{
			name:     "Script Block Context",
			htmlBody: "<html><script>var a = 'pwned_payload';</script></html>",
			expected: "Script Block",
		},
		{
			name:     "Attribute Value Context",
			htmlBody: "<input type='text' value='pwned_payload'>",
			expected: "Attribute Value (input[value])",
		},
		{
			name:     "Attribute Name Context",
			htmlBody: "<svg pwned_payload='1'>",
			expected: "Attribute Name (svg)",
		},
		{
			name:     "HTML Comment Context",
			htmlBody: "<!-- pwned_payload -->", // ← fix: payload add kiya
			expected: "HTML Comment",
		},
		{
			name:     "No Reflection",
			htmlBody: "<html><body>Safe body</body></html>",
			expected: "Unknown Context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineContext([]byte(tt.htmlBody), payload)
			require.Equal(t, tt.expected, result)
		})
	}
}
