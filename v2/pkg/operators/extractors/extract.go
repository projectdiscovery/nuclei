package extractors

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"

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
	e.SaveToFile(results)
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
	e.SaveToFile(results)
	return results
}

// ExtractXPath extracts items from text using XPath selectors
func (e *Extractor) ExtractXPath(corpus string) map[string]struct{} {
	if strings.HasPrefix(corpus, "<?xml") {
		return e.ExtractXML(corpus)
	}
	return e.ExtractHTML(corpus)
}

// ExtractHTML extracts items from HTML using XPath selectors
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
	e.SaveToFile(results)
	return results
}

// ExtractXML extracts items from XML using XPath selectors
func (e *Extractor) ExtractXML(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return results
	}

	for _, k := range e.XPath {
		nodes, err := xmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}
		for _, node := range nodes {
			var value string

			if e.Attribute != "" {
				value = node.SelectAttr(e.Attribute)
			} else {
				value = node.InnerText()
			}
			if _, ok := results[value]; !ok {
				results[value] = struct{}{}
			}
		}
	}
	e.SaveToFile(results)
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
	e.SaveToFile(results)
	return results
}

// ExtractDSL execute the expression and returns the results
func (e *Extractor) ExtractDSL(data map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})

	for _, compiledExpression := range e.dslCompiled {
		result, err := compiledExpression.Evaluate(data)
		// ignore errors that are related to missing parameters
		// eg: dns dsl can have all the parameters that are not present
		if err != nil && !strings.HasPrefix(err.Error(), "No parameter") {
			return results
		}

		if result != nil {
			resultString := fmt.Sprint(result)
			if resultString != "" {
				results[resultString] = struct{}{}
			}
		}
	}
	e.SaveToFile(results)
	return results
}
