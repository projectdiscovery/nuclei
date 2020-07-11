package workflows

import (
	"strings"
	"sync"

	tengo "github.com/d5/tengo/v2"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/executor"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
)

// NucleiVar within the scripting engine
type NucleiVar struct {
	tengo.ObjectImpl
	Templates    []*Template
	URL          string
	InternalVars map[string]interface{}
	sync.RWMutex
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
	n.InternalVars = make(map[string]interface{})
	externalVars := make(map[string]string)

	// if external variables are specified and matches the template ones, these gets overwritten
	if len(args) == 1 {
		m := args[0]
		if m.CanIterate() {
			i := m.Iterate()
			for i.Next() {
				key, ok := tengo.ToString(i.Key())
				if !ok {
					continue
				}
				value, ok := tengo.ToString(i.Value())
				if !ok {
					continue
				}
				externalVars[key] = value
			}
		}
	}

	var gotResult bool
	for _, template := range n.Templates {
		if template.HTTPOptions != nil {
			for _, request := range template.HTTPOptions.Template.RequestsHTTP {
				request.Payloads = generators.MergeMapsWithStrings(request.Payloads, externalVars)
				template.HTTPOptions.HTTPRequest = request
				httpExecutor, err := executor.NewHTTPExecutor(template.HTTPOptions)
				if err != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, err)
					continue
				}
				result := httpExecutor.ExecuteHTTP(n.URL)
				if result.Error != nil {
					gologger.Warningf("Could not send request for template '%s': %s\n", template.HTTPOptions.Template.ID, result.Error)
					continue
				}

				if httpExecutor.GotResults() {
					gotResult = true
					n.addResults(&result)
				}
			}
		}

		if template.DNSOptions != nil {
			for _, request := range template.DNSOptions.Template.RequestsDNS {
				template.DNSOptions.DNSRequest = request
				dnsExecutor := executor.NewDNSExecutor(template.DNSOptions)
				result := dnsExecutor.ExecuteDNS(n.URL)
				if result.Error != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, result.Error)
					continue
				}

				if dnsExecutor.GotResults() {
					gotResult = true
					n.addResults(&result)
				}
			}
		}
	}

	if gotResult {
		return tengo.TrueValue, nil
	}
	return tengo.FalseValue, nil
}

func (n *NucleiVar) IsFalsy() bool {
	n.RLock()
	defer n.RUnlock()

	return len(n.InternalVars) == 0
}

func (n *NucleiVar) addResults(r *executor.Result) {
	n.RLock()
	defer n.RUnlock()

	for k, v := range r.Matches {
		n.InternalVars[k] = v
	}

	for k, v := range r.Extractions {
		n.InternalVars[k] = v
	}
}

// IndexGet returns the value for the given key.
func (n *NucleiVar) IndexGet(index tengo.Object) (res tengo.Object, err error) {
	strIdx, ok := tengo.ToString(index)
	if !ok {
		err = tengo.ErrInvalidIndexType
		return
	}

	r, ok := n.InternalVars[strIdx]
	if !ok {
		return tengo.UndefinedValue, nil
	}

	// Probably can be improved but as of now just joining all extractors with new line
	res = &tengo.String{Value: strings.Join(r.([]string), "\n")}

	return
}
