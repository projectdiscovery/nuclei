package templates

import (
	"fmt"
	"os"

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

		if request.MatchersCondition == "" {
			request.MCondition = matchers.ANDCondition
		} else {
			// compile the condition type
			var ok bool
			request.MCondition, ok = matchers.ConditionTypes[request.MatchersCondition]
			if !ok {
				return nil, fmt.Errorf("unknown condition specified: %s", request.MatchersCondition)
			}
		}
	}

	// Compile the matchers and the extractors for dns requests
	for _, request := range template.RequestsDNS {
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

		if request.MatchersCondition == "" {
			request.MCondition = matchers.ANDCondition
		} else {
			// compile the condition type
			var ok bool
			request.MCondition, ok = matchers.ConditionTypes[request.MatchersCondition]
			if !ok {
				return nil, fmt.Errorf("unknown condition specified: %s", request.MatchersCondition)
			}
		}
	}

	return template, nil
}
