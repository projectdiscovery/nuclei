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

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) []string {
	return e.regexCompiled.FindAllString(corpus, -1)
}
