package templates

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/http"
)

// Template is a request workflow parsed from a yaml file
type Template struct {
	// MaintainSession specifies whether to maintain request session
	MaintainSession bool `yaml:"maintain-session"`
	// RequestsCondition specifies the condition of the requests
	RequestsCondition bool `yaml:"requests-condition"`

	// DNS contains the DNS requests to make to the targets.
	DNS []*dns.Request `yaml:"dns"`

	// HTTP requests to make for the template to the targets.
	// TODO: deprecate requests in future going with only HTTP
	HTTP         []*http.Request `yaml:"http"`
	HTTPRequests []*http.Request `yaml:"requests"`
}

// CompiledTemplate is the compiled template workflow parsed from yaml file.
type CompiledTemplate struct {
	MaintainSession   bool
	RequestsCondition bool

	DNS  []*dns.CompiledRequest
	HTTP []*http.CompiledRequest
}

// Compile compiles a template performing all processing structure.
func (t *Template) Compile() (*CompiledTemplate, error) {
	if len(t.DNS) > 0 && (len(t.HTTP) > 0 || len(t.HTTPRequests) > 0) {
		return nil, errors.New("http and dns requests can't be used together")
	}

	compiled := &CompiledTemplate{
		MaintainSession:   t.MaintainSession,
		RequestsCondition: t.RequestsCondition,
	}

	for _, dns := range t.DNS {
		req, err := dns.Compile()
		if err != nil {
			return nil, errors.Wrap(err, "could not compile dns request")
		}
		compiled.DNS = append(compiled.DNS, req)
	}
	for _, http := range t.HTTP {
		req, err := http.Compile()
		if err != nil {
			return nil, errors.Wrap(err, "could not compile http request")
		}
		compiled.HTTP = append(compiled.HTTP, req)
	}
	for _, http := range t.HTTPRequests {
		req, err := http.Compile()
		if err != nil {
			return nil, errors.Wrap(err, "could not compile http request")
		}
		compiled.HTTP = append(compiled.HTTP, req)
	}
	return compiled, nil
}
