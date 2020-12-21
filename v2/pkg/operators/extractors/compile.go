package extractors

import (
	"fmt"
	"regexp"
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

	// Setup the part of the request to match, if any.
	if e.Part != "" {
		e.part, ok = PartTypes[e.Part]
		if !ok {
			return fmt.Errorf("unknown matcher part specified: %s", e.Part)
		}
	} else {
		e.part = BodyPart
	}

	return nil
}
