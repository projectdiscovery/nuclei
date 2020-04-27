package extractors

// Extract extracts response from the parts of request using a regex
func (e *Extractor) Extract(body, headers string) map[string]struct{} {
	// Match the parts as required for regex check
	if e.part == BodyPart {
		return e.extractRegex(body)
	} else if e.part == HeaderPart {
		return e.extractRegex(headers)
	} else {
		matches := e.extractRegex(headers)
		if len(matches) > 0 {
			return matches
		}
		return e.extractRegex(body)
	}
}

// ExtractDNS extracts response from dns message using a regex
func (e *Extractor) ExtractDNS(msg string) map[string]struct{} {
	// Match the parts as required for regex check
	return e.extractRegex(msg)
}

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	for _, regex := range e.regexCompiled {
		matches := regex.FindAllString(corpus, -1)
		for _, match := range matches {
			results[match] = struct{}{}
		}
	}
	return results
}
