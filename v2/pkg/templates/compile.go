package templates

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
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

	template.path = file

	// If no requests, and it is also not a workflow, return error.
	if len(template.RequestsHTTP)+len(template.RequestsDNS)+len(template.RequestsNetwork) <= 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the matchers and the extractors for http requests
	for _, request := range template.RequestsHTTP {
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
			switch pt := payload.(type) {
			case string:
				// check if it's a multiline string list
				if len(strings.Split(pt, "\n")) <= 1 {
					// check if it's a worldlist file
					if !generators.FileExists(pt) {
						// attempt to load the file by taking the full path, tokezining it and searching the template in such paths
						changed := false
						pathTokens := strings.Split(template.path, "/")

						for i := range pathTokens {
							tpath := path.Join(strings.Join(pathTokens[:i], "/"), pt)
							if generators.FileExists(tpath) {
								request.Payloads[name] = tpath
								changed = true

								break
							}
						}

						if !changed {
							return nil, fmt.Errorf("the %s file for payload %s does not exist or does not contain enough elements", pt, name)
						}
					}
				}
			case []string, []interface{}:
				if len(payload.([]interface{})) == 0 {
					return nil, fmt.Errorf("the payload %s does not contain enough elements", name)
				}
			default:
				return nil, fmt.Errorf("the payload %s has invalid type", name)
			}
		}

		for _, matcher := range request.Matchers {
			if matchErr := matcher.CompileMatchers(); matchErr != nil {
				return nil, errors.Wrap(matchErr, "could not compile extractor")
			}
		}

		for _, extractor := range request.Extractors {
			if extractErr := extractor.CompileExtractors(); extractErr != nil {
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
			if matchErr := matcher.CompileMatchers(); matchErr != nil {
				return nil, errors.Wrap(matchErr, "could not compile matchers")
			}
		}

		for _, extractor := range request.Extractors {
			if extractErr := extractor.CompileExtractors(); extractErr != nil {
				return nil, errors.Wrap(extractErr, "could not compile extractor")
			}
		}
	}

	// Compile the matchers and the extractors for dns requests
	for _, request := range template.RequestsNetwork {
		request.GeneratePort()
		// Get the condition between the matchers
		condition, ok := matchers.ConditionTypes[request.MatchersCondition]
		if !ok {
			request.SetMatchersCondition(matchers.ORCondition)
		} else {
			request.SetMatchersCondition(condition)
		}

		for _, matcher := range request.Matchers {
			if matchErr := matcher.CompileMatchers(); matchErr != nil {
				return nil, errors.Wrap(matchErr, "could not compile matchers")
			}
		}

		for _, extractor := range request.Extractors {
			if extractErr := extractor.CompileExtractors(); extractErr != nil {
				return nil, errors.Wrap(extractErr, "could not compile extractor")
			}
		}
	}

	return template, nil
}
