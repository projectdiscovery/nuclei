package extractors

import (
	"encoding/json"
	"strings"

	"github.com/antchfx/htmlquery"

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
	if e.CaseInsensitive {
		inputData := data
		data = make(map[string]interface{}, len(inputData))
		for k, v := range inputData {
			if s, ok := v.(string); ok {
				v = strings.ToLower(s)
			}
			data[strings.ToLower(k)] = v
		}
	}

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

// ExtractHTML extracts items from text using XPath selectors
func (e *Extractor) ExtractHTML(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return results
	}
	for _, k := range e.XPath {
		nodes, err := htmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}
		for _, node := range nodes {
			var value string

			if e.Attribute != "" {
				value = htmlquery.SelectAttr(node, e.Attribute)
			} else {
				value = htmlquery.InnerText(node)
			}
			if _, ok := results[value]; !ok {
				results[value] = struct{}{}
			}
		}
	}
	return results
}

// ExtractJSON extracts text from a corpus using JQ queries and returns it
func (e *Extractor) ExtractJSON(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	var jsonObj interface{}

	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
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
			var result string
			if res, err := types.JSONScalarToString(v); err == nil {
				result = res
			} else if res, err := json.Marshal(v); err == nil {
				result = string(res)
			} else {
				result = types.ToString(v)
			}
			if _, ok := results[result]; !ok {
				results[result] = struct{}{}
			}
		}
	}
	return results
}
