package extractors

import (
	"fmt"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"golang.org/x/net/html"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// ExtractRegex extracts text from a corpus and returns it
func (e *Extractor) ExtractRegex(corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	groupPlusOne := e.RegexGroup + 1
	for _, regex := range e.regexCompiled {
		// skip prefix short-circuit for case-insensitive patterns
		rstr := regex.String()
		if !strings.Contains(rstr, "(?i") {
			if prefix, ok := regex.LiteralPrefix(); ok && prefix != "" {
				if !strings.Contains(corpus, prefix) {
					continue
				}
			}
		}

		submatches := regex.FindAllStringSubmatch(corpus, -1)

		for _, match := range submatches {
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

// ExtractKval extracts key value pairs from a data map.
//
// For the case-insensitive variant we previously copied the entire input map
// and lower-cased every key plus every string value. This was O(event size)
// per extractor invocation regardless of how many KVal entries we actually
// queried (typically 1-3 keys against a map that can hold dozens of headers
// and full body fields). The new implementation scans the source map only
// for matches against the requested KVal entries via strings.EqualFold,
// then lower-cases hits in place. No event-wide copy.
func (e *Extractor) ExtractKval(data map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})
	if e.CaseInsensitive {
		for _, k := range e.KVal {
			for srcKey, srcVal := range data {
				if !strings.EqualFold(srcKey, k) {
					continue
				}
				itemString := types.ToString(srcVal)
				if s, ok := srcVal.(string); ok {
					itemString = strings.ToLower(s)
				} else {
					itemString = strings.ToLower(itemString)
				}
				if _, present := results[itemString]; !present {
					results[itemString] = struct{}{}
				}
			}
		}
		return results
	}

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

// ExtractXPath extracts items from text using XPath selectors
func (e *Extractor) ExtractXPath(corpus string) map[string]struct{} {
	if strings.HasPrefix(corpus, "<?xml") {
		return e.ExtractXML(corpus)
	}
	return e.ExtractHTML(corpus)
}

// ExtractHTML extracts items from HTML using XPath selectors. Parses the
// corpus on every call. Protocol callers with access to the per-response
// body cache should prefer ExtractHTMLNode.
func (e *Extractor) ExtractHTML(corpus string) map[string]struct{} {
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return make(map[string]struct{})
	}
	return e.ExtractHTMLNode(doc)
}

// ExtractHTMLNode extracts items from a pre-parsed HTML node using XPath
// selectors.
func (e *Extractor) ExtractHTMLNode(doc *html.Node) map[string]struct{} {
	results := make(map[string]struct{})
	if doc == nil {
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

// ExtractXML extracts items from XML using XPath selectors. Parses the
// corpus on every call. Protocol callers with access to the per-response
// body cache should prefer ExtractXMLNode.
func (e *Extractor) ExtractXML(corpus string) map[string]struct{} {
	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return make(map[string]struct{})
	}
	return e.ExtractXMLNode(doc)
}

// ExtractXMLNode extracts items from a pre-parsed XML node using XPath
// selectors.
func (e *Extractor) ExtractXMLNode(doc *xmlquery.Node) map[string]struct{} {
	results := make(map[string]struct{})
	if doc == nil {
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
	return results
}

// ExtractJSON extracts text from a corpus using JQ queries. Unmarshals on
// every call. Protocol callers with access to the per-response body cache
// should prefer ExtractJSONObject to share the unmarshaled value across
// multiple json extractors.
func (e *Extractor) ExtractJSON(corpus string) map[string]struct{} {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
		return make(map[string]struct{})
	}
	return e.ExtractJSONObject(jsonObj)
}

// ExtractJSONObject runs the compiled jq programs against an already
// unmarshaled JSON value.
func (e *Extractor) ExtractJSONObject(jsonObj interface{}) map[string]struct{} {
	results := make(map[string]struct{})
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
	return results
}
