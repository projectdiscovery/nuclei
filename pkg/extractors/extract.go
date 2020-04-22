package extractors

// Extract extracts response from the parts of request using a regex
func (e *Extractor) Extract(body, headers string) []string {
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
func (e *Extractor) ExtractDNS(msg string) []string {
	// Match the parts as required for regex check
	return e.extractRegex(msg)
}

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) []string {
	results := []string{}
	for _, regex := range e.regexCompiled {
		results = append(results, regex.FindAllString(corpus, -1)...)
	}
	return results
}
