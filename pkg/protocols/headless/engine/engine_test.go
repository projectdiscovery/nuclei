package engine

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLaunchBrowserFallsBackFromChromeShell(t *testing.T) {
	var paths []string
	got, err := launchBrowser("/cache/chrome-headless-shell", func(path string) (string, error) {
		paths = append(paths, path)
		if path != "" {
			return "", errors.New("shell launch failed")
		}
		return "ws://default-browser", nil
	})

	require.NoError(t, err)
	require.Equal(t, "ws://default-browser", got)
	require.Equal(t, []string{"/cache/chrome-headless-shell", ""}, paths)
}

func TestLaunchBrowserDoesNotRetryDefaultBrowser(t *testing.T) {
	var calls int
	expected := errors.New("default launch failed")
	_, err := launchBrowser("", func(string) (string, error) {
		calls++
		return "", expected
	})

	require.ErrorIs(t, err, expected)
	require.Equal(t, 1, calls)
}
