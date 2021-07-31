package extractors

import (
	"encoding/json"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// ExtractRegex extracts text from a corpus and returns it
func (e *Extractor) ExtractRegex(corpus string) map[string]struct{} {
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

// ExtractKval extracts key value pairs from a data map
func (e *Extractor) ExtractKval(data map[string]interface{}) map[string]struct{} {
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

// ExtractJson extracts key value pairs from a data map
func (e *Extractor) ExtractJson(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	var jsonObj interface{}

	err := json.Unmarshal([]byte(corpus), &jsonObj)

	if err != nil {
		return results
	}

	for _, k := range e.jsonCompiled {
		iter := k.Run(jsonObj)
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if _, ok := v.(error); ok {
				break
			}
			bytes, err := json.Marshal(v)
			if err != nil {
				break
			}
			results[string(bytes)] = struct{}{}
		}
	}

	return results
}
