package workflows

import (
	"github.com/d5/tengo/v2"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/executor"
)

// NucleiVar within the scripting engine
type NucleiVar struct {
	tengo.ObjectImpl
	Templates []*Template
	URL       string
}

// Template contains HTTPOptions and DNSOptions for a single template
type Template struct {
	HTTPOptions *executor.HTTPOptions
	DNSOptions  *executor.DNSOptions
}

// TypeName of the variable
func (n *NucleiVar) TypeName() string {
	return "nuclei-var"
}

// CanCall can be called from within the scripting engine
func (n *NucleiVar) CanCall() bool {
	return true
}

// Call logic - actually it doesn't require arguments
func (n *NucleiVar) Call(args ...tengo.Object) (ret tengo.Object, err error) {
	var gotResult bool

	for _, template := range n.Templates {
		if template.HTTPOptions != nil {
			for _, request := range template.HTTPOptions.Template.RequestsHTTP {
				template.HTTPOptions.HTTPRequest = request
				httpExecutor, err := executor.NewHTTPExecutor(template.HTTPOptions)
				if err != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, err)
					continue
				}
				err = httpExecutor.ExecuteHTTP(n.URL)
				if err != nil {
					gologger.Warningf("Could not send request for template '%s': %s\n", template.HTTPOptions.Template.ID, err)
					continue
				}
				if httpExecutor.GotResults() {
					gotResult = true
				}
			}
		}

		if template.DNSOptions != nil {
			for _, request := range template.DNSOptions.Template.RequestsDNS {
				template.DNSOptions.DNSRequest = request
				dnsExecutor := executor.NewDNSExecutor(template.DNSOptions)
				err = dnsExecutor.ExecuteDNS(n.URL)
				if err != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, err)
					continue
				}
				if dnsExecutor.GotResults() {
					gotResult = true
				}
			}
		}
	}
	if gotResult {
		return tengo.TrueValue, nil
	}
	return tengo.FalseValue, nil
}
