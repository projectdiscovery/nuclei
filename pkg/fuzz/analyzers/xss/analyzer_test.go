package xss

import (
	"fmt"
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
			htmlBody: fmt.Sprintf("<html><body>Hello %s world</body></html>", payload),
			expected: "HTML Text",
		},
		{
			name:     "Script Block Context",
			htmlBody: fmt.Sprintf("<html><script>var a = '%s';</script></html>", payload),
			expected: "Script Block",
		},
		{
			name:     "Attribute Value Context",
			htmlBody: fmt.Sprintf("<input type='text' value='%s'>", payload),
			expected: "Attribute Value (input[value])",
		},
		{
			name:     "Attribute Name Context",
			htmlBody: fmt.Sprintf("<svg %s='1'>", payload),
			expected: "Attribute Name (svg)",
		},
		{
			name:     "HTML Comment Context",
			htmlBody: fmt.Sprintf("<!-- %s -->", payload),
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
