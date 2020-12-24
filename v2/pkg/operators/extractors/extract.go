package extractors

import "github.com/projectdiscovery/nuclei/v2/pkg/types"

// Extract extracts data from an output structure based on user options
func (e *Extractor) Extract(data map[string]interface{}) map[string]struct{} {
	part, ok := data[e.Part]
	if !ok {
		return nil
	}
	partString := types.ToString(part)

	switch e.extractorType {
	case RegexExtractor:
		return e.extractRegex(partString)
	case KValExtractor:
		return e.extractKVal(data)
	}
	return nil
}

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	groupPlusOne := e.RegexGroup + 1
	for _, regex := range e.regexCompiled {
		matches := regex.FindAllStringSubmatch(corpus, -1)

		for _, match := range matches {
			if len(match) < groupPlusOne {
				continue
			}
			matchString := match[e.RegexGroup]

			if _, ok := results[matchString]; !ok {
				results[matchString] = struct{}{}
			}
		}
	}
	return results
}

// extractKVal extracts key value pairs from a data map
func (e *Extractor) extractKVal(data map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})

	for _, k := range e.KVal {
		item, ok := data[k]
		if !ok {
			continue
		}
		itemString := types.ToString(item)
		if _, ok := results[itemString]; !ok {
			results[itemString] = struct{}{}
		}
	}
	return results
}
