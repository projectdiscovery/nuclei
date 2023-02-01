package utils

import (
	"fmt"
	"path"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	urlutil "github.com/projectdiscovery/utils/url"
)

// GenerateVariables will create default variables with context args
func GenerateVariablesWithContextArgs(input *contextargs.Context, trailingSlash bool) map[string]interface{} {
	parsed, err := urlutil.Parse(input.MetaInput.Input)
	if err != nil {
		return nil
	}
	return GenerateVariablesWithURL(parsed, trailingSlash, contextargs.GenerateVariables(input))
}

// GenerateVariables will create default variables after parsing a url with additional variables
func GenerateVariablesWithURL(inputURL *urlutil.URL, trailingSlash bool, additionalVars map[string]interface{}) map[string]interface{} {
	parsed := inputURL.Clone()
	// Query parameter merging is handled elsewhere and should not be included in {{BaseURL}} or other httpVariables
	parsed.Params = make(urlutil.Params)
	domain := parsed.Host
	if strings.Contains(parsed.Host, ":") {
		domain = strings.Split(parsed.Host, ":")[0]
	}

	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else if parsed.Scheme == "http" {
			port = "80"
		}
	}

	if trailingSlash {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}

	escapedPath := parsed.EscapedPath()
	directory := path.Dir(escapedPath)
	if directory == "." {
		directory = ""
	}
	base := path.Base(escapedPath)
	if base == "." {
		base = ""
	}
	httpVariables := map[string]interface{}{
		"BaseURL":  parsed.String(),
		"RootURL":  fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host),
		"Hostname": parsed.Host,
		"Host":     domain,
		"Port":     port,
		"Path":     directory,
		"File":     base,
		"Scheme":   parsed.Scheme,
	}
	return generators.MergeMaps(httpVariables, dns.GenerateVariables(domain), additionalVars)
}
