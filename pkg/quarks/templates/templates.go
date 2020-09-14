package templates

import (
	"net/http"

	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/dns"
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
