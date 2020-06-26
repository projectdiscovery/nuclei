package workflows

import (
	"github.com/d5/tengo/v2"
	"github.com/projectdiscovery/nuclei/pkg/executor"
)

// NucleiVar within the scripting engine
type NucleiVar struct {
	tengo.ObjectImpl
	HTTPOptions *executor.HTTPOptions
	DNSOptions  *executor.DNSOptions
	URL         string
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
	for _, request := range n.HTTPOptions.Template.RequestsHTTP {
		n.HTTPOptions.HTTPRequest = request
		httpExecutor, err := executor.NewHTTPExecutor(n.HTTPOptions)
		if err != nil {
			return nil, err
		}
		err = httpExecutor.ExecuteHTTP(n.URL)
		if err != nil {
			return nil, err
		}
		if httpExecutor.GotResults() {
			return tengo.TrueValue, nil
		}
		return tengo.FalseValue, nil
	}

	for _, request := range n.DNSOptions.Template.RequestsDNS {
		n.DNSOptions.DNSRequest = request
		dnsExecutor := executor.NewDNSExecutor(n.DNSOptions)
		err = dnsExecutor.ExecuteDNS(n.URL)
		if err != nil {
			return nil, err
		}
		if dnsExecutor.GotResults() {
			return tengo.TrueValue, nil
		}
		return tengo.FalseValue, nil
	}

	return nil, nil
}
