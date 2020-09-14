package templates

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/http"
)

// Template is a request workflow parsed from a yaml file
type Template struct {
	// HTTP requests to make for the template to the targets.
	// TODO: deprecate requests in future going with only HTTP
	HTTPRequests []http.Request `yaml:"requests"`
	HTTP         []http.Request `yaml:"http"`

	// DNS contains the DNS requests to make to the targets.
	DNS []dns.Request `yaml:"dns"`
}

// CompiledTemplate is the compiled template workflow parsed from yaml file.
type CompiledTemplate struct {
	DNS  []dns.CompiledRequest
	HTTP []http.CompiledRequest
}
