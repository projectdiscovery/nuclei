package templates

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
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

	// If no requests, and it is also not a workflow, return error.
	if len(template.RequestsDNS)+len(template.RequestsDNS)+len(template.Workflows) <= 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the requests found
	for _, request := range template.RequestsDNS {
		if err := request.Compile(options); err != nil {
			return nil, errors.Wrap(err, "could not compile dns request")
		}
		template.totalRequests += request.Requests()
	}
	for _, request := range template.RequestsHTTP {
		if err := request.Compile(options); err != nil {
			return nil, errors.Wrap(err, "could not compile dns request")
		}
		template.totalRequests += request.Requests()
	}
	return template, nil
}
