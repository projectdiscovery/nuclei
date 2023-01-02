package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnwrapError(t *testing.T) {
	require.Equal(t, nil, UnwrapError(nil))

	errOne := fmt.Errorf("error one")
	require.Equal(t, errOne, UnwrapError(errOne))

	errTwo := fmt.Errorf("error with error: %w", errOne)
	require.Equal(t, errOne, UnwrapError(errTwo))

	errThree := fmt.Errorf("error with error: %w", errTwo)
	require.Equal(t, errOne, UnwrapError(errThree))
}

func TestParseURL(t *testing.T) {
	testcases := []struct {
		URL      string
		Hostname string
	}{
		{"https://scanme.sh:443", "scanme.sh:443"},
		{"http://scanme.sh/path", "scanme.sh"},
		{"scanme.sh:443/path", "scanme.sh:443"},
		{"scanme.sh/path", "scanme.sh"},
	}
	for _, v := range testcases {
		urlx := ParseHostname(v.URL)
		if urlx == "" {
			t.Errorf("failed to hostname of url %v", v)
		}
		if urlx != v.Hostname {
			t.Errorf("hostname mismatch expected scanme.sh got %v", urlx)
		}
	}
}
