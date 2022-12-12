package utils

import (
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestVariables(t *testing.T) {
	baseURL := "http://localhost:9001/test/123"
	parsed, _ := url.Parse(baseURL)
	values := GenerateVariablesWithURL(parsed, true, nil)

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
	values = GenerateVariablesWithURL(parsed, false, nil)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "example.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "https://example.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "443", "incorrect port number")
	require.Equal(t, values["Scheme"], "https", "incorrect scheme")
	require.Equal(t, values["Hostname"], "example.com", "incorrect hostname")

	baseURL = "ftp://foobar.com/"
	parsed, _ = url.Parse(baseURL)
	values = GenerateVariablesWithURL(parsed, true, nil)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "foobar.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "ftp://foobar.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "", "incorrect port number") // Unsupported protocol results in a blank port
	require.Equal(t, values["Scheme"], "ftp", "incorrect scheme")
	require.Equal(t, values["Hostname"], "foobar.com", "incorrect hostname")

	baseURL = "http://scanme.sh"
	ctxArgs := contextargs.NewWithInput(baseURL)
	ctxArgs.MetaInput.CustomIP = "1.2.3.4"
	values = GenerateVariablesWithContextArgs(ctxArgs, true)

	require.Equal(t, values["BaseURL"], baseURL, "incorrect baseurl")
	require.Equal(t, values["Host"], "scanme.sh", "incorrect domain name")
	require.Equal(t, values["RootURL"], "http://scanme.sh", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "80", "incorrect port number")
	require.Equal(t, values["Scheme"], "http", "incorrect scheme")
	require.Equal(t, values["Hostname"], "scanme.sh", "incorrect hostname")
	require.Equal(t, values["ip"], "1.2.3.4", "incorrect ip")
}
