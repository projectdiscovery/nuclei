package templates

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"gopkg.in/yaml.v2"
)

// Parse parses a yaml request template file
func Parse(file string, options *protocols.ExecuterOptions) (*Template, error) {
	template := &Template{}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(f).Decode(template)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Setting up variables regarding template metadata
	template.path = file
	options.TemplateID = template.ID
	options.TemplateInfo = template.Info
	options.TemplatePath = file

	// We don't support both http and dns in a single template
	if len(template.RequestsDNS) > 0 && len(template.RequestsHTTP) > 0 {
		return nil, fmt.Errorf("both http and dns requests for %s", template.ID)
	}
	// If no requests, and it is also not a workflow, return error.
	if len(template.RequestsDNS)+len(template.RequestsDNS)+len(template.Workflows) == 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the requests found
	for _, request := range template.RequestsDNS {
		template.totalRequests += request.Requests()
	}
	for _, request := range template.RequestsHTTP {
		template.totalRequests += request.Requests()
	}
	if len(template.RequestsDNS) > 0 {
		template.executer = dns.NewExecuter(template.RequestsDNS, options)
		err = template.executer.Compile()
	}
	if len(template.RequestsHTTP) > 0 {
		template.executer = http.NewExecuter(template.RequestsHTTP, options)
		err = template.executer.Compile()
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not compile request")
	}
	return template, nil
}
