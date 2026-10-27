package engine

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLaunchBrowserFallsBackFromChromeShell(t *testing.T) {
	var paths []string
	got, err := launchBrowser("/cache/chrome-headless-shell", true, func(path string) (string, error) {
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
	_, err := launchBrowser("", false, func(string) (string, error) {
		calls++
		return "", expected
	})

	require.ErrorIs(t, err, expected)
	require.Equal(t, 1, calls)
}

func TestLaunchBrowserDoesNotRetryInstalledChrome(t *testing.T) {
	var paths []string
	expected := errors.New("installed chrome launch failed")
	_, err := launchBrowser("/usr/bin/google-chrome", false, func(path string) (string, error) {
		paths = append(paths, path)
		return "", expected
	})

	require.ErrorIs(t, err, expected)
	require.Equal(t, []string{"/usr/bin/google-chrome"}, paths)
}

// The browser download goes through the scan proxy, or the environment proxy
// when there is none.
func TestDownloadProxy(t *testing.T) {
	cases := []struct {
		name string
		opts *types.Options
		want string
	}{
		{"no proxy uses the environment", &types.Options{}, ""},
		{"http proxy", &types.Options{AliveHttpProxy: "http://127.0.0.1:8080"}, "http://127.0.0.1:8080"},
		{"socks proxy", &types.Options{AliveSocksProxy: "socks5://127.0.0.1:1080"}, "socks5://127.0.0.1:1080"},
	}
	for _, c := range cases {
		if got := downloadProxy(c.opts); got != c.want {
			t.Errorf("%s: downloadProxy()=%q want %q", c.name, got, c.want)
		}
	}
}
