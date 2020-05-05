package templates

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/nuclei/pkg/generators"
	"github.com/projectdiscovery/nuclei/pkg/matchers"
	"gopkg.in/yaml.v2"
)

// ParseTemplate parses a yaml request template file
func ParseTemplate(file string) (*Template, error) {
	template := &Template{}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(f).Decode(template)
	if err != nil {
		f.Close()
		return nil, err
	}
	f.Close()

	// Compile the matchers and the extractors for http requests
	for _, request := range template.RequestsHTTP {
		// Get the condition between the matchers
		condition, ok := matchers.ConditionTypes[request.MatchersCondition]
		if !ok {
			request.SetMatchersCondition(matchers.ANDCondition)
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
		for name, wordlist := range request.Payloads {
			if !generators.FileExists(wordlist) {
				return nil, fmt.Errorf("The %s file for payload %s does not exist", wordlist, name)
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
	}

	// Compile the matchers and the extractors for dns requests
	for _, request := range template.RequestsDNS {
		// Get the condition between the matchers
		condition, ok := matchers.ConditionTypes[request.MatchersCondition]
		if !ok {
			request.SetMatchersCondition(matchers.ANDCondition)
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
