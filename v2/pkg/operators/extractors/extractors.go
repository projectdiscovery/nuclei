package extractors

import (
	"regexp"

	"github.com/itchyny/gojq"
)

// Extractor is used to extract part of response using a regex.
type Extractor struct {
	// description: |
	//   Name of the extractor. Name should be lowercase and must not contain
	//   spaces or underscores (_).
	// examples:
	//   - value: "\"cookie-extractor\""
	Name string `yaml:"name,omitempty" jsonschema:"title=name of the extractor,description=Name of the extractor"`
	// description: |
	//   Type is the type of the extractor.
	// values:
	//   - "regex"
	//   - "kval"
	//   - "json"
	//   - "xpath"
	Type string `yaml:"type" jsonschema:"title=type of the extractor,description=Type of the extractor,enum=regex,enum=kval,enum=json,enum=xpath"`
	// extractorType is the internal type of the extractor
	extractorType ExtractorType

	// description: |
	//   Regex contains the regular expression patterns to extract from a part.
	//
	//   Go regex engine does not support lookaheads or lookbehinds, so as a result
	//   they are also not supported in nuclei.
	// examples:
	//   - name: Braintree Access Token Regex
	//     value: >
	//       []string{"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"}
	//   - name: Wordpress Author Extraction regex
	//     value: >
	//       []string{"Author:(?:[A-Za-z0-9 -\\_=\"]+)?<span(?:[A-Za-z0-9 -\\_=\"]+)?>([A-Za-z0-9]+)<\\/span>"}
	Regex []string `yaml:"regex,omitempty" jsonschema:"title=regex to extract from part,description=Regex to extract from part"`
	// description: |
	//   Group specifies a numbered group to extract from the regex.
	// examples:
	//   - name: Example Regex Group
	//     value: "1"
	RegexGroup int `yaml:"group,omitempty" jsonschema:"title=group to extract from regex,description=Group to extract from regex"`
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp

	// description: |
	//   kval contains the key-value pairs present in the HTTP response header.
	//   kval extractor can be used to extract HTTP response header and cookie key-value pairs.
	//   kval extractor inputs are case-insensitive, and does not support dash (-) in input which can replaced with underscores (_)
	// 	 For example, Content-Type should be replaced with content_type
	//
	//   A list of supported parts is available in docs for request types.
	// examples:
	//   - name: Extract Server Header From HTTP Response
	//     value: >
	//       []string{"server"}
	//   - name: Extracting value of PHPSESSID Cookie
	//     value: >
	//       []string{"phpsessid"}
	//   - name: Extracting value of Content-Type Cookie
	//     value: >
	//       []string{"content_type"}
	KVal []string `yaml:"kval,omitempty" jsonschema:"title=kval pairs to extract from response,description=Kval pairs to extract from response"`

	// description: |
	//   JSON allows using jq-style syntax to extract items from json response
	//
	// examples:
	//   - value: >
	//       []string{".[] | .id"}
	//   - value: >
	//       []string{".batters | .batter | .[] | .id"}
	JSON []string `yaml:"json,omitempty" jsonschema:"title=json jq expressions to extract data,description=JSON JQ expressions to evaluate from response part"`
	// description: |
	//   XPath allows using xpath expressions to extract items from html response
	//
	// examples:
	//   - value: >
	//       []string{"/html/body/div/p[2]/a"}
	XPath []string `yaml:"xpath,omitempty" jsonschema:"title=html xpath expressions to extract data,description=XPath allows using xpath expressions to extract items from html response"`
	// description: |
	//   Attribute is an optional attribute to extract from response XPath.
	//
	// examples:
	//   - value: "\"href\""
	Attribute string `yaml:"attribute,omitempty" jsonschema:"title=optional attribute to extract from xpath,description=Optional attribute to extract from response XPath"`

	// jsonCompiled is the compiled variant
	jsonCompiled []*gojq.Code

	// description: |
	//   Part is the part of the request response to extract data from.
	//
	//   Each protocol exposes a lot of different parts which are well
	//   documented in docs for each request type.
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `yaml:"part,omitempty" jsonschema:"title=part of response to extract data from,description=Part of the request response to extract data from"`
	// description: |
	//   Internal, when set to true will allow using the value extracted
	//   in the next request for some protocols (like HTTP).
	Internal bool `yaml:"internal,omitempty" jsonschema:"title=mark extracted value for internal variable use,description=Internal when set to true will allow using the value extracted in the next request for some protocols"`
}

// ExtractorType is the type of the extractor specified
type ExtractorType = int

const (
	// RegexExtractor extracts responses with regexes
	RegexExtractor ExtractorType = iota + 1
	// KValExtractor extracts responses with key:value
	KValExtractor
	// XPathExtractor extracts responses with Xpath selectors
	XPathExtractor
	// JSONExtractor extracts responses with json
	JSONExtractor
)

// ExtractorTypes is a table for conversion of extractor type from string.
var ExtractorTypes = map[string]ExtractorType{
	"regex": RegexExtractor,
	"kval":  KValExtractor,
	"xpath": XPathExtractor,
	"json":  JSONExtractor,
}

// GetType returns the type of the matcher
func (e *Extractor) GetType() ExtractorType {
	return e.extractorType
}
