package utils

import (
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var AllKnownVariables = append(KnownHTTPVariables, KnownDNSVariables...)

// KnownHTTPVariables is the list of known http variables
var KnownHTTPVariables = []string{"BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme"}

// GenerateVariables will create default variables with context args
func GenerateVariablesWithContextArgs(input *contextargs.Context, trailingSlash bool) map[string]interface{} {
	parsed, err := urlutil.Parse(input.MetaInput.Input)
	if err != nil {
		return nil
	}
	return GenerateHTTPVariablesWithURL(parsed, trailingSlash, contextargs.GenerateVariables(input))
}

// GenerateVariables will create default variables after parsing a url with additional variables
func GenerateHTTPVariablesWithURL(inputURL *urlutil.URL, trailingSlash bool, additionalVars map[string]interface{}) map[string]interface{} {
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
	httpVariables := make(map[string]interface{})

	for _, k := range KnownHTTPVariables {
		switch k {
		case "BaseURL":
			httpVariables[k] = parsed.String()
		case "RootURL":
			httpVariables[k] = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		case "Hostname":
			httpVariables[k] = parsed.Host
		case "Host":
			httpVariables[k] = domain
		case "Port":
			httpVariables[k] = port
		case "Path":
			httpVariables[k] = directory
		case "File":
			httpVariables[k] = base
		case "Scheme":
			httpVariables[k] = parsed.Scheme
		}
	}

	return generators.MergeMaps(httpVariables, additionalVars)
}

// KnownDNSVariables contains the list of known variables for dns requests
var KnownDNSVariables = []string{"FQDN", "RDN", "DN", "TLD", "SD"}

// GenerateDNSVariables from a dns name
func GenerateDNSVariables(domain string) map[string]interface{} {
	parsed, err := publicsuffix.Parse(strings.TrimSuffix(domain, "."))
	if err != nil {
		return map[string]interface{}{"FQDN": domain}
	}

	domainName := strings.Join([]string{parsed.SLD, parsed.TLD}, ".")
	dnsVariables := make(map[string]interface{})
	for _, k := range KnownDNSVariables {
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

// KnownTCPVariables contains the list of known variables for tcp requests
var KnownTCPVariables = []string{"Host", "Port", "Hostname"}

func GenerateNetworkVariables(input string) map[string]interface{} {
	if !strings.Contains(input, ":") {
		return map[string]interface{}{"Hostname": input, "Host": input}
	}
	host, port, err := net.SplitHostPort(input)
	if err != nil {
		return map[string]interface{}{"Hostname": input}
	}
	var tcpVariables = make(map[string]interface{})
	for _, k := range KnownTCPVariables {
		switch k {
		case "Host":
			tcpVariables[k] = host
		case "Port":
			tcpVariables[k] = port
		case "Hostname":
			tcpVariables[k] = input
		}
	}
	return tcpVariables
}

// KnownWebSocketVariables contains the list of known variables for websocket requests
var KnownWebSocketVariables = []string{"Hostname", "Host", "Scheme", "Path"}

func GetWebsocketVariables(input *urlutil.URL) map[string]interface{} {
	websocketVariables := make(map[string]interface{})

	websocketVariables["Hostname"] = input.Host
	websocketVariables["Host"] = input.Hostname()
	websocketVariables["Scheme"] = input.Scheme
	requestPath := input.Path
	if values := urlutil.GetParams(input.URL.Query()); len(values) > 0 {
		requestPath = requestPath + "?" + values.Encode()
	}
	websocketVariables["Path"] = requestPath
	return websocketVariables
}

var KnowneWhoISVariables = []string{"Input", "Hostname", "Host"}

// GenerateWhoISVariables will create default variables after parsing a url
func GenerateWhoISVariables(input string) map[string]interface{} {
	var domain string

	parsed, err := urlutil.Parse(input)
	if err != nil {
		return map[string]interface{}{"Input": input}
	}
	domain = parsed.Host
	if domain == "" {
		domain = input
	}
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	return map[string]interface{}{
		"Input":    input,
		"Hostname": parsed.Host,
		"Host":     domain,
	}
}
