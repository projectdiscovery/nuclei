package templates

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/imdario/mergo"
	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"gopkg.in/yaml.v2"
)

// extendMatcher tries to use the matcher as specified in the Matcher.Extends field as the base for this matcher: any
// additionally defined field will not be overridden by the template's ones.
func extendMatcher(allMatchers map[string]*matchers.Matcher, matcher *matchers.Matcher) error {
	if referenced, found := allMatchers[matcher.Extends]; found {
		if referenced.NeedsExtension() {
			err := extendMatcher(allMatchers, referenced)
			if err != nil {
				return err
			}
		}
		err := mergo.Merge(matcher, referenced)
		if err != nil {
			return fmt.Errorf("could not inherit from '%s' for matcher definition '%s': %s", referenced.Name, matcher.Name, err)
		}
		matcher.SetExtended()
	} else {
		return fmt.Errorf("could not find referenced matcher '%s' from '%s'", matcher.Extends, matcher.Name)
	}
	return nil
}

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
		return nil, errors.New("No requests defined")
	}

	// builds a map of all the matchers
	matchersMap := make(map[string]*matchers.Matcher)
	for _, request := range template.BulkRequestsHTTP {
		for _, matcher := range request.Matchers {
			if matcher.NeedsExtension() {
				// requires a new name
				if matcher.Name == "" {
					return nil, fmt.Errorf("an extending matcher is required to also provide a new name")
				}
				// already present
				if _, already := matchersMap[matcher.Name]; already {
					return nil, fmt.Errorf("a matcher with name '%s' is defined multiple times", matcher.Name)
				}
			}
			matchersMap[matcher.Name] = matcher
		}
	}

	// resolves matcher definitions extending other matchers (templates), merge the fields and overwrite the template's
	// ones with the provided values
	for _, m := range matchersMap {
		if m.NeedsExtension() {
			err := extendMatcher(matchersMap, m)
			if err != nil {
				return nil, fmt.Errorf("could not extend matcher '%s': %s", m.Name, err)
			}
		}
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
						// attempt to load the file by taking the full path, tokezining it and searching the template in such paths
						changed := false
						pathTokens := strings.Split(template.path, "/")
						for i := range pathTokens {
							tpath := path.Join(strings.Join(pathTokens[:i], "/"), v)
							if generators.FileExists(tpath) {
								request.Payloads[name] = tpath
								changed = true
								break
							}
						}
						if !changed {
							return nil, fmt.Errorf("The %s file for payload %s does not exist or does not contain enough elements", v, name)
						}
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
