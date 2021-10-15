package extractors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/itchyny/gojq"
)

// CompileExtractors performs the initial setup operation on an extractor
func (e *Extractor) CompileExtractors() error {
	var ok bool
	// Set up the extractor type
	e.extractorType, ok = ExtractorTypes[e.Type]
	if !ok {
		return fmt.Errorf("unknown extractor type specified: %s", e.Type)
	}

	// Compile the regexes
	for _, regex := range e.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		e.regexCompiled = append(e.regexCompiled, compiled)
	}

	for i, kval := range e.KVal {
		e.KVal[i] = strings.ToLower(kval)
	}

	for _, query := range e.JSON {
		query, err := gojq.Parse(query)
		if err != nil {
			return fmt.Errorf("could not parse json: %s", query)
		}
		compiled, err := gojq.Compile(query)
		if err != nil {
			return fmt.Errorf("could not compile json: %s", query)
		}
		e.jsonCompiled = append(e.jsonCompiled, compiled)
	}

	// Set up the part of the request to match, if any.
	if e.Part == "" {
		e.Part = "body"
	}
	return nil
}
