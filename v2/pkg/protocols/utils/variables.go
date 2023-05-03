package utils

import (
	"fmt"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// KnownVariables are the variables that are known to input requests
var KnownVariables = []string{"BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme", "Input", "FQDN", "RDN", "DN", "TLD", "SD"}

// GenerateVariables will create default variables with context args
func GenerateVariablesWithContextArgs(input *contextargs.Context, trailingSlash bool) map[string]interface{} {
	parsed, err := urlutil.Parse(input.MetaInput.Input)
	if err != nil {
		return nil
	}
	return GenerateVariables(parsed, trailingSlash, contextargs.GenerateVariables(input))
}

// GenerateDNSVariables from a dns name
// This function is used by dns and ssl protocol to generate variables
func GenerateDNSVariables(domain string) map[string]interface{} {
	parsed, err := publicsuffix.Parse(strings.TrimSuffix(domain, "."))
	if err != nil {
		return map[string]interface{}{"FQDN": domain}
	}

	domainName := strings.Join([]string{parsed.SLD, parsed.TLD}, ".")
	dnsVariables := make(map[string]interface{})
	for _, k := range KnownVariables {
		switch k {
		case "FQDN":
			dnsVariables[k] = domain
		case "RDN":
			dnsVariables[k] = domainName
		case "DN":
			dnsVariables[k] = parsed.SLD
		case "TLD":
			dnsVariables[k] = parsed.TLD
		case "SD":
			dnsVariables[k] = parsed.TRD
		}
	}
	return dnsVariables
}

// GenerateVariables accepts string or *urlutil.URL object as input
// Returns the map of KnownVariables keys
// This function is used by http, headless, websocket, network and whois protocols to generate protocol variables
func GenerateVariables(input interface{}, removeTrailingSlash bool, additionalVars map[string]interface{}) map[string]interface{} {

	var vars = make(map[string]interface{})
	switch input := input.(type) {
	case string:
		parsed, err := urlutil.Parse(input)
		if err != nil {
			return map[string]interface{}{"Input": input, "Hostname": input}
		}
		vars = generateVariables(parsed, removeTrailingSlash)
	case *urlutil.URL:
		vars = generateVariables(input, removeTrailingSlash)
	case urlutil.URL:
		vars = generateVariables(&input, removeTrailingSlash)
	default:
		// return a non-fatal error
		gologger.Error().Msgf("unknown type %T for input %v", input, input)
	}
	return generators.MergeMaps(vars, additionalVars)
}

func generateVariables(inputURL *urlutil.URL, removeTrailingSlash bool) map[string]interface{} {
	parsed := inputURL.Clone()
	parsed.Params = make(urlutil.Params)
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else if parsed.Scheme == "http" {
			port = "80"
		}
	}
	if removeTrailingSlash {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}
	escapedPath := parsed.EscapedPath()
	requestPath := path.Dir(escapedPath)
	if requestPath == "." {
		requestPath = ""
	}

	base := path.Base(escapedPath)
	if base == "." {
		base = ""
	}

	if parsed.Scheme == "ws" {
		if values := urlutil.GetParams(parsed.URL.Query()); len(values) > 0 {
			requestPath = escapedPath + "?" + values.Encode()
		}
	}
	knownVariables := make(map[string]interface{})
	for _, k := range KnownVariables {
		switch k {
		case "BaseURL":
			knownVariables[k] = parsed.String()
		case "RootURL":
			knownVariables[k] = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		case "Hostname":
			knownVariables[k] = parsed.Host
		case "Host":
			knownVariables[k] = parsed.Hostname()
		case "Port":
			knownVariables[k] = port
		case "Path":
			knownVariables[k] = requestPath
		case "File":
			knownVariables[k] = base
		case "Scheme":
			knownVariables[k] = parsed.Scheme
		case "Input":
			knownVariables[k] = parsed.String()
		}
	}
	return generators.MergeMaps(knownVariables, GenerateDNSVariables(parsed.Hostname()))
}
