package templates

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Parse parses a yaml request template file
func Parse(file string) (*Template, error) {
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

	template.path = file

	// If no requests, and it is also not a workflow, return error.
	if len(template.BulkRequestsHTTP)+len(template.RequestsDNS) <= 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the matchers and the extractors for http requests
	for _, request := range template.BulkRequestsHTTP {

		request.InitGenerator()
	}

	return template, nil
}
