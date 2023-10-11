package utils

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestHTTPVariables(t *testing.T) {
	baseURL := "http://localhost:9001/test/123"
	parsed, _ := urlutil.Parse(baseURL)
	// trailing slash is only true when both target/inputURL and payload {{BaseURL}}/xyz both have slash
	values := GenerateVariables(parsed, false, nil)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["RootURL"], "http://localhost:9001", "incorrect rootURL")
	require.Equal(t, values["Host"], "localhost", "incorrect domain name")
	require.Equal(t, values["Path"], "/test", "incorrect path")
	require.Equal(t, values["File"], "123", "incorrect file")
	require.Equal(t, values["Port"], "9001", "incorrect port number")
	require.Equal(t, values["Scheme"], "http", "incorrect scheme")
	require.Equal(t, values["Hostname"], "localhost:9001", "incorrect hostname")

	baseURL = "https://example.com"
	parsed, _ = urlutil.Parse(baseURL)
	values = GenerateVariables(parsed, false, nil)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "example.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "https://example.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "", "incorrect path")
	require.Equal(t, values["Port"], "443", "incorrect port number")
	require.Equal(t, values["Scheme"], "https", "incorrect scheme")
	require.Equal(t, values["Hostname"], "example.com", "incorrect hostname")

	baseURL = "ftp://foobar.com/"
	parsed, _ = urlutil.Parse(baseURL)
	values = GenerateVariables(parsed, false, nil)

	require.Equal(t, values["BaseURL"], parsed.String(), "incorrect baseurl")
	require.Equal(t, values["Host"], "foobar.com", "incorrect domain name")
	require.Equal(t, values["RootURL"], "ftp://foobar.com", "incorrect rootURL")
	require.Equal(t, values["Path"], "/", "incorrect path")
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

func TestGenerateDNSVariables(t *testing.T) {
	vars := GenerateDNSVariables("www.projectdiscovery.io")
	require.Equal(t, map[string]interface{}{
		"FQDN": "www.projectdiscovery.io",
		"RDN":  "projectdiscovery.io",
		"DN":   "projectdiscovery",
		"TLD":  "io",
		"SD":   "www",
	}, vars, "could not get dns variables")
}

func TestGenerateVariablesForDNS(t *testing.T) {
	vars := GenerateVariables("www.projectdiscovery.io", false, nil)
	expected := map[string]interface{}{
		"FQDN": "www.projectdiscovery.io",
		"RDN":  "projectdiscovery.io",
		"DN":   "projectdiscovery",
		"TLD":  "io",
		"SD":   "www",
	}
	checkResults(t, vars, expected)
}

func TestGenerateVariablesForTCP(t *testing.T) {
	vars := GenerateVariables("127.0.0.1:5431", false, nil)
	expected := map[string]interface{}{
		"Host":     "127.0.0.1",
		"Port":     "5431",
		"Hostname": "127.0.0.1:5431",
	}
	checkResults(t, vars, expected)

	vars = GenerateVariables("127.0.0.1", false, nil)
	expected = map[string]interface{}{
		"Host":     "127.0.0.1",
		"Hostname": "127.0.0.1",
	}
	checkResults(t, vars, expected)
}

func TestGenerateWhoISVariables(t *testing.T) {
	vars := GenerateVariables("https://example.com", false, nil)
	expected := map[string]interface{}{
		"Host": "example.com", "Hostname": "example.com", "Input": "https://example.com",
	}
	checkResults(t, vars, expected)

	vars = GenerateVariables("https://example.com:8080", false, nil)
	expected = map[string]interface{}{
		"Host": "example.com", "Hostname": "example.com:8080", "Input": "https://example.com:8080",
	}
	checkResults(t, vars, expected)
}

func TestGetWebsocketVariables(t *testing.T) {
	baseURL := "ws://127.0.0.1:40221"
	parsed, _ := urlutil.Parse(baseURL)
	vars := GenerateVariables(parsed, false, nil)
	expected := map[string]interface{}{
		"Host":     "127.0.0.1",
		"Hostname": "127.0.0.1:40221",
		"Scheme":   "ws",
		"Path":     "",
	}
	checkResults(t, vars, expected)

	baseURL = "ws://127.0.0.1:40221/test?var=test"
	parsed, _ = urlutil.Parse(baseURL)
	vars = GenerateVariables(parsed, false, nil)
	expected = map[string]interface{}{
		"Host":     "127.0.0.1",
		"Hostname": "127.0.0.1:40221",
		"Scheme":   "ws",
		"Path":     "/test?var=test",
	}
	checkResults(t, vars, expected)
}

// checkResults returns true if mapSubset is a subset of mapSet otherwise false
func checkResults(t *testing.T, mapSet interface{}, mapSubset interface{}) {

	got := reflect.ValueOf(mapSet)
	expected := reflect.ValueOf(mapSubset)

	require.Greater(t, len(expected.MapKeys()), 0, "failed expected value is empty")
	require.Greater(t, len(got.MapKeys()), 0, "failed expected value is empty")

	require.LessOrEqual(t, len(expected.MapKeys()), len(got.MapKeys()), "failed return value more than expected")

	iterMapSubset := expected.MapRange()

	for iterMapSubset.Next() {
		k := iterMapSubset.Key()
		v := iterMapSubset.Value()

		value := got.MapIndex(k)

		if !value.IsValid() || v.Interface() != value.Interface() {
			require.Equal(t, value, v, "failed return value is not equal to expected")
		}
	}
}
