package extractors

import (
	"fmt"
	"regexp"
	"strings"
)

// CompileExtractors performs the initial setup operation on a extractor
func (e *Extractor) CompileExtractors() error {
	var ok bool
	// Setup the extractor type
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

	// Setup the part of the request to match, if any.
	if e.Part == "" {
		e.Part = "body"
	}
	return nil
}
