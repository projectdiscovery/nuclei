package utils

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVariables(t *testing.T) {
	baseURL := "http://localhost:9001/test/123"
	parsed, _ := url.Parse(baseURL)
	values := GenerateVariables(parsed, true)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["RootURL"], "http://localhost:9001", "incorrect rootURL")
	require.Equal(t, values["Host"], "localhost", "incorrect domain name")
	require.Equal(t, values["Path"], "/test", "incorrect path")
	require.Equal(t, values["File"], "123", "incorrect file")
	require.Equal(t, values["Port"], "9001", "incorrect port number")
	require.Equal(t, values["Scheme"], "http", "incorrect scheme")
	require.Equal(t, values["Hostname"], "localhost:9001", "incorrect hostname")

	baseURL = "https://example.com"
	parsed, _ = url.Parse(baseURL)
	values = GenerateVariables(parsed, false)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "example.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "https://example.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "443", "incorrect port number")
	require.Equal(t, values["Scheme"], "https", "incorrect scheme")
	require.Equal(t, values["Hostname"], "example.com", "incorrect hostname")

	baseURL = "ftp://foobar.com/"
	parsed, _ = url.Parse(baseURL)
	values = GenerateVariables(parsed, true)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "foobar.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "ftp://foobar.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "", "incorrect port number") // Unsupported protocol results in a blank port
	require.Equal(t, values["Scheme"], "ftp", "incorrect scheme")
	require.Equal(t, values["Hostname"], "foobar.com", "incorrect hostname")
}
