package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateContentLength(t *testing.T) {
	tests := []struct {
		name                string
		expected            int64
		contentLengthHeader int64
		bodyLength          int64
	}{
		{"content-length-header", 10, 10, 10},
		{"content-length-header-with-body-length", 10, 10, 1000},
		{"no-content-length-header-with-body-length", 1000, -1, 1000},
		{"content-length-header-without-body-length", 10, 10, -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CalculateContentLength(test.contentLengthHeader, test.bodyLength)
			require.Equal(t, test.expected, got)
		})
	}
}
