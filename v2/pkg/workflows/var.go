package workflows

import (
	"sync"

	tengo "github.com/d5/tengo/v2"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/atomicboolean"
	"github.com/projectdiscovery/nuclei/v2/pkg/executer"
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
	HTTPOptions *executer.HTTPOptions
	DNSOptions  *executer.DNSOptions
}

// TypeName of the variable
func (n *NucleiVar) TypeName() string {
	return "nuclei-var"
}

// CanCall can be called from within the scripting engine
func (n *NucleiVar) CanCall() bool {
	return true
}

// Call logic - args[0]=headers, args[1]=payloads
func (n *NucleiVar) Call(args ...tengo.Object) (ret tengo.Object, err error) {
	n.InternalVars = make(map[string]interface{})
	headers := make(map[string]string)
	externalVars := make(map[string]interface{})

	// if external variables are specified and matches the template ones, these gets overwritten
	if len(args) >= 1 {
		headers = iterableToMapString(args[0])
	}

	// if external variables are specified and matches the template ones, these gets overwritten
	if len(args) >= 2 {
		externalVars = iterableToMap(args[1])
	}

	var gotResult atomicboolean.AtomBool
	for _, template := range n.Templates {
		if template.HTTPOptions != nil {
			for _, request := range template.HTTPOptions.Template.BulkRequestsHTTP {
				// apply externally supplied payloads if any
				request.Headers = generators.MergeMapsWithStrings(request.Headers, headers)
				// apply externally supplied payloads if any
				request.Payloads = generators.MergeMaps(request.Payloads, externalVars)
				template.HTTPOptions.BulkHttpRequest = request
				httpExecuter, err := executer.NewHTTPExecuter(template.HTTPOptions)
				if err != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, err)
					continue
				}
				result := httpExecuter.ExecuteHTTP(n.URL)
				if result.Error != nil {
					gologger.Warningf("Could not send request for template '%s': %s\n", template.HTTPOptions.Template.ID, result.Error)
					continue
				}

				if result.GotResults {
					gotResult.Or(result.GotResults)
					n.addResults(&result)
				}
			}
		}

		if template.DNSOptions != nil {
			for _, request := range template.DNSOptions.Template.RequestsDNS {
				template.DNSOptions.DNSRequest = request
				dnsExecuter := executer.NewDNSExecuter(template.DNSOptions)
				result := dnsExecuter.ExecuteDNS(n.URL)
				if result.Error != nil {
					gologger.Warningf("Could not compile request for template '%s': %s\n", template.HTTPOptions.Template.ID, result.Error)
					continue
				}

				if result.GotResults {
					gotResult.Or(result.GotResults)
					n.addResults(&result)
				}
			}
		}
	}

	if gotResult.Get() {
		return tengo.TrueValue, nil
	}
	return tengo.FalseValue, nil
}

func (n *NucleiVar) IsFalsy() bool {
	n.RLock()
	defer n.RUnlock()

	return len(n.InternalVars) == 0
}

func (n *NucleiVar) addResults(r *executer.Result) {
	n.RLock()
	defer n.RUnlock()

	// add payload values as first, they will be accessible if not overwritter through
	// payload_name (from template) => value
	for k, v := range r.Meta {
		n.InternalVars[k] = v
	}

	for k := range r.Matches {
		n.InternalVars[k] = true
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

	switch r.(type) {
	case bool:
		if r.(bool) {
			res = tengo.TrueValue
		} else {
			res = tengo.FalseValue
		}
	case string:
		res = &tengo.String{Value: r.(string)}
	case []string:
		rr, ok := r.([]string)
		if !ok {
			break
		}
		var resA []tengo.Object
		for _, rrr := range rr {
			resA = append(resA, &tengo.String{Value: rrr})
		}
		res = &tengo.Array{Value: resA}
	}

	return
}

func iterableToMap(t tengo.Object) map[string]interface{} {
	m := make(map[string]interface{})
	if t.CanIterate() {
		i := t.Iterate()
		for i.Next() {
			key, ok := tengo.ToString(i.Key())
			if !ok {
				continue
			}
			value := tengo.ToInterface(i.Value())
			m[key] = value
		}
	}

	return m
}

func iterableToMapString(t tengo.Object) map[string]string {
	m := make(map[string]string)
	if t.CanIterate() {
		i := t.Iterate()
		for i.Next() {
			key, ok := tengo.ToString(i.Key())
			if !ok {
				continue
			}
			if value, ok := tengo.ToString(i.Value()); ok {
				m[key] = value
			}
		}
	}

	return m
}
