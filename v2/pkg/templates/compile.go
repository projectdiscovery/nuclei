package templates

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
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

	// If no requests, and it is also not a workflow, return error.
	if len(template.BulkRequestsHTTP)+len(template.RequestsDNS) <= 0 {
		return nil, errors.New("No requests defined")
	}

	// Compile the matchers and the extractors for http requests
	for _, request := range template.BulkRequestsHTTP {
		// Get the condition between the matchers
		condition, ok := matchers.ConditionTypes[request.MatchersCondition]
		if !ok {
			request.SetMatchersCondition(matchers.ORCondition)
		} else {
			request.SetMatchersCondition(condition)
		}

		// Set the attack type - used only in raw requests
		attack, ok := generators.AttackTypes[request.AttackType]
		if !ok {
			request.SetAttackType(generators.Sniper)
		} else {
			request.SetAttackType(attack)
		}

		// Validate the payloads if any
		for name, payload := range request.Payloads {
			switch payload.(type) {
			case string:
				v := payload.(string)
				// check if it's a multiline string list
				if len(strings.Split(v, "\n")) <= 1 {
					// check if it's a worldlist file
					if !generators.FileExists(v) {
						return nil, fmt.Errorf("The %s file for payload %s does not exist or does not contain enough elements", v, name)
					}
				}
			case []string, []interface{}:
				if len(payload.([]interface{})) <= 0 {
					return nil, fmt.Errorf("The payload %s does not contain enough elements", name)
				}
			default:
				return nil, fmt.Errorf("The payload %s has invalid type", name)
			}
		}

		for _, matcher := range request.Matchers {
			if err = matcher.CompileMatchers(); err != nil {
				return nil, err
			}
		}

		for _, extractor := range request.Extractors {
			if err := extractor.CompileExtractors(); err != nil {
				return nil, err
			}
		}

		request.InitGenerator()
	}

	// Compile the matchers and the extractors for dns requests
	for _, request := range template.RequestsDNS {
		// Get the condition between the matchers
		condition, ok := matchers.ConditionTypes[request.MatchersCondition]
		if !ok {
			request.SetMatchersCondition(matchers.ORCondition)
		} else {
			request.SetMatchersCondition(condition)
		}

		for _, matcher := range request.Matchers {
			if err = matcher.CompileMatchers(); err != nil {
				return nil, err
			}
		}

		for _, extractor := range request.Extractors {
			if err := extractor.CompileExtractors(); err != nil {
				return nil, err
			}
		}
	}

	return template, nil
}
